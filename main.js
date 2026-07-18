// ==========================================
// DEVELOPER CONFIGURATION
// ==========================================
// Set to true to enable the hidden Developer Options in the Settings tab 
// (allows downloading specific past versions for testing).
const DEV_MODE = false;
// ==========================================

const { Plugin, PluginSettingTab, Setting, Notice, Modal, MarkdownRenderer, ItemView, WorkspaceLeaf, ToggleComponent, TFile } = require('obsidian');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const https = require('https');
// Note: the plain `http` module is intentionally NOT required — DownloadManager is
// https-only (see assertSafeDownloadUrl below) and has no legitimate use for it.
const { URL } = require('url');
const crypto = require('crypto');

const VIEW_TYPE_GATE_MANAGER = "gate-manager-view";

// Safe path-boundary check: is `child` inside (or equal to) `parent`?
// A plain `child.startsWith(path.resolve(parent))` is NOT safe — e.g. parent
// "/tmp/gate-extract" is a string-prefix of the sibling directory
// "/tmp/gate-extract-evil", so a crafted archive entry name could resolve to a path
// outside the intended directory while still passing that check. Using path.relative()
// and rejecting any result that starts with ".." (or is absolute, on Windows drive-swap
// cases) closes that gap.
function isPathInside(child, parent) {
	const resolvedParent = path.resolve(parent);
	const resolvedChild = path.resolve(child);
	if (resolvedChild === resolvedParent) return true;
	const relative = path.relative(resolvedParent, resolvedChild);
	return !!relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
}

// Hosts the DownloadManager is allowed to connect to — both for the initial download URL
// and for every hop of a redirect chain. This plugin downloads and extracts arbitrary
// content into the user's vault, so it deliberately does NOT follow redirects to whatever
// host a server-controlled `Location` header happens to point to; only GitHub's own
// asset-serving infrastructure is trusted. If GitHub changes its release-asset CDN hostnames
// in the future, downloads will start failing closed with a clear "untrusted host" error
// rather than silently fetching from somewhere else — update this list if that happens.
const TRUSTED_DOWNLOAD_HOSTS_EXACT = new Set([
	'github.com',
	'api.github.com',
	'codeload.github.com',
	'raw.githubusercontent.com'
]);
const TRUSTED_DOWNLOAD_HOST_SUFFIX = '.githubusercontent.com'; // covers objects./release-assets./github-cloud.githubusercontent.com etc.

function isTrustedDownloadHost(hostname) {
	if (!hostname) return false;
	const host = hostname.toLowerCase();
	return TRUSTED_DOWNLOAD_HOSTS_EXACT.has(host) || host.endsWith(TRUSTED_DOWNLOAD_HOST_SUFFIX);
}

// Fail-closed validation used both for the initial download URL and for every redirect hop.
// Throws (rather than returning a boolean) so callers can't accidentally ignore the result.
function assertSafeDownloadUrl(urlString) {
	let parsed;
	try {
		parsed = new URL(urlString);
	} catch (e) {
		throw new Error(`Blocked download: malformed URL.`);
	}
	if (parsed.protocol !== 'https:') {
		throw new Error(`Blocked insecure download: only https:// URLs are allowed (got ${parsed.protocol})`);
	}
	if (!isTrustedDownloadHost(parsed.hostname)) {
		throw new Error(`Blocked download: untrusted host "${parsed.hostname}". Only official GitHub hosts are allowed.`);
	}
	return parsed;
}

// --- Secret storage for the GitHub token ------------------------------------------------
// Obsidian's plugin data file (data.json) is plain, unencrypted JSON on disk. Where the
// platform supports it, we additionally encrypt the token at rest using Electron's
// OS-level `safeStorage` API — Keychain on macOS, DPAPI on Windows, libsecret/kwallet on
// Linux (the same mechanism most Electron desktop apps use for storing secrets). This is
// best-effort and NOT guaranteed available on every platform/build (e.g. some Linux
// desktops have no secret-storage backend installed at all), so it always falls back to
// plain-text storage rather than losing the token — and the settings UI tells the user
// plainly which mode is actually active, so nothing is silently "more secure" than it is.
const TokenCrypto = {
	_safeStorage: null,
	_checked: false,
	_getSafeStorage() {
		if (this._checked) return this._safeStorage;
		this._checked = true;
		try {
			const electron = require('electron');
			if (electron && electron.safeStorage && typeof electron.safeStorage.isEncryptionAvailable === 'function' && electron.safeStorage.isEncryptionAvailable()) {
				this._safeStorage = electron.safeStorage;
			}
		} catch (e) {
			this._safeStorage = null; // 'electron' not requirable, or safeStorage missing on this build/platform
		}
		return this._safeStorage;
	},
	isAvailable() {
		return !!this._getSafeStorage();
	},
	// Returns a marker-prefixed, base64-encoded ciphertext, or null if encryption isn't
	// available (caller should fall back to plain-text storage in that case).
	encrypt(plainText) {
		const ss = this._getSafeStorage();
		if (!ss || !plainText) return null;
		try {
			return 'v1:' + ss.encryptString(plainText).toString('base64');
		} catch (e) {
			console.error('[GATE Manager] Token encryption failed, falling back to plain text storage:', e);
			return null;
		}
	},
	// Returns the decrypted string, or null if it can't be decrypted (moved to a different
	// machine/OS user account, corrupted, or encryption unavailable on this platform).
	decrypt(stored) {
		if (!stored || typeof stored !== 'string' || !stored.startsWith('v1:')) return null;
		const ss = this._getSafeStorage();
		if (!ss) return null;
		try {
			return ss.decryptString(Buffer.from(stored.slice(3), 'base64'));
		} catch (e) {
			console.error('[GATE Manager] Token decryption failed (moved to a different machine/user account?):', e);
			return null;
		}
	}
};

// Define the default configuration for the plugin.
const DEFAULT_SETTINGS = {
	repositoryOwner: "anandrajbaghel",
	repositoryName: "gate-vault",
	autoCheckUpdates: false,
	openVaultAfterInstall: false,
	enableNotifications: true,
	releaseChannel: "stable",
	hasCompletedOnboarding: false,
	exclusionFilter: ".obsidian, scripts, tools, .gitattributes, CODE_OF_CONDUCT.md, CONTRIBUTING.md, INDEX_GENERATOR_SPEC.md, INDEX_SPEC.md, INSTALL_PLAN_SPEC.md, LICENSE, README.md, SPEC.md, UPDATE_POLICY.md, VAULT_RULES_SPEC.md, VAULT_SPEC.md, vault-index.json, vault-manifest.json, vault-rules.json",
	autoOpenChangelog: true,
	devTargetVersion: "",
	lastUpdateCheckTime: 0, // For rate limiting API checks (applies to ALL check types now)
	githubToken: "", // Optional GitHub Personal Access Token, held in memory at runtime.
	                  // Raises the API rate limit from 60 req/hr (shared per network IP) to
	                  // 5,000 req/hr (per-token), and is required for automatic background
	                  // update checks (see checkForUpdates). NOT written to disk in plain
	                  // text when OS-level encryption is available — see githubTokenEncrypted
	                  // and TokenCrypto above / _settingsForDisk() below.
	githubTokenEncrypted: "" // The token as actually persisted to data.json when TokenCrypto
	                          // encryption is available on this platform (see saveSettings /
	                          // _persistSettings / loadSettings). Empty when encryption isn't
	                          // available, in which case githubToken itself is written in
	                          // plain text instead (Obsidian's data.json has no built-in
	                          // encryption either way).
};

/**
 * FormatUtils provides reusable formatting methods.
 */
class FormatUtils {
	static bytes(bytes, decimals = 2) {
		if (!+bytes) return '0 Bytes';
		const k = 1024, dm = decimals < 0 ? 0 : decimals;
		const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
	}
}

/**
 * VersionUtils provides reusable helper methods for semantic versioning.
 */
class VersionUtils {
	static compareVersions(v1, v2) {
		if (!v1 && !v2) return 0;
		if (!v1) return -1;
		if (!v2) return 1;

		const cleanV1 = v1.replace(/[^0-9.]/g, '');
		const cleanV2 = v2.replace(/[^0-9.]/g, '');

		const parts1 = cleanV1.split('.').map(Number);
		const parts2 = cleanV2.split('.').map(Number);

		const maxLength = Math.max(parts1.length, parts2.length);

		for (let i = 0; i < maxLength; i++) {
			const num1 = parts1[i] || 0;
			const num2 = parts2[i] || 0;
			if (num1 > num2) return 1;
			if (num1 < num2) return -1;
		}
		return 0;
	}
}

// ==========================================
// CORE CLASSES
// ==========================================

const ActionType = {
	INSTALL: 'INSTALL',
	UPDATE: 'UPDATE',
	CONFLICT: 'CONFLICT',
	MERGE: 'MERGE',
	ARCHIVE: 'ARCHIVE',
	IGNORE: 'IGNORE',
	SKIP: 'SKIP'
};

const ActionPriority = {
	ARCHIVE: 100,
	INSTALL: 200,
	UPDATE: 300,
	CONFLICT: 400,
	MERGE: 500,
	IGNORE: 600,
	SKIP: 700
};

class Action {
	constructor(config) {
		this.id = config.id || '';
		this.type = config.type;
		this.path = config.path;
		this.priority = config.priority;
		this.status = 'PENDING';
		this.reason = config.reason || '';
		this.repositoryEntry = config.repositoryEntry || null;
		this.localEntry = config.localEntry || null;
		this.stateEntry = config.stateEntry || null;
		this.warnings = config.warnings || [];
		this.errors = config.errors || [];
		
		this.isMandatory = config.isMandatory || false;

		if (config.source) this.source = config.source;
		if (config.destination) this.destination = config.destination;
		if (config.repositoryHash) this.repositoryHash = config.repositoryHash;
		if (config.installedHash) this.installedHash = config.installedHash;
		if (config.currentHash) this.currentHash = config.currentHash;
		if (config.oldHash) this.oldHash = config.oldHash;
		if (config.newHash) this.newHash = config.newHash;
		if (config.compareAvailable !== undefined) this.compareAvailable = config.compareAvailable;
		if (config.resolution) this.resolution = config.resolution;
		if (config.mergeStrategy) this.mergeStrategy = config.mergeStrategy;
		if (config.repositoryFile) this.repositoryFile = config.repositoryFile;
		if (config.localFile) this.localFile = config.localFile;
		if (config.archiveDestination) this.archiveDestination = config.archiveDestination;
		if (config.removedVersion) this.removedVersion = config.removedVersion;
		if (config.estimatedBytes) this.estimatedBytes = config.estimatedBytes;
	}
}

class InstallPlan {
	constructor(actions, summary, statistics, validation) {
		this.actions = Object.freeze([...actions]);
		this.executionOrder = Object.freeze(actions.map(a => a.id));
		this.summary = Object.freeze(summary);
		this.statistics = Object.freeze(statistics);
		this.validation = Object.freeze(validation);
		this.warnings = Object.freeze([...validation.warnings]);
		this.errors = Object.freeze([...validation.errors]);
		Object.freeze(this);
	}
}

class PlanningResult {
	constructor(repoModel, vaultModel, stateModel, plan, summary, stats, validation, duration) {
		this.repositoryModel = repoModel;
		this.localVaultModel = vaultModel;
		this.stateModel = stateModel;
		this.installPlan = plan;
		this.summary = Object.freeze(summary);
		this.statistics = Object.freeze(stats);
		this.validation = Object.freeze(validation);
		this.warnings = Object.freeze([...validation.warnings]);
		this.errors = Object.freeze([...validation.errors]);
		this.plannerVersion = "1.0.0";
		this.planningTimestamp = Date.now();
		this.planningDuration = duration;
		this.isValid = validation.isValid;
		Object.freeze(this);
	}
}

class RuleEngine {
	constructor(rules) {
		this.rules = rules || {};
		this.defaultOwnership = this.rules.ownership || 'Repository';
		this.defaultMergeStrategy = this.rules.mergeStrategy || 'Ours';
		this.ruleList = Array.isArray(this.rules.rules) ? this.rules.rules : [];
	}

	_getMatchingRule(relativePath) {
		let match = null;
		for (const rule of this.ruleList) {
			// Fix: Implement proper path-segment matching to avoid false positives (e.g. "Resources Backup" matching "Resources")
			if (rule.path && (relativePath === rule.path || relativePath.startsWith(rule.path + '/'))) {
				if (!match || rule.path.length > match.path.length) {
					match = rule;
				}
			}
		}
		return match;
	}

	getOwnership(relativePath) {
		const rule = this._getMatchingRule(relativePath);
		return rule && rule.ownership ? rule.ownership : this.defaultOwnership;
	}

	getMergeStrategy(relativePath) {
		const rule = this._getMatchingRule(relativePath);
		return rule && rule.mergeStrategy ? rule.mergeStrategy : this.defaultMergeStrategy;
	}
	
	getArchivePolicy(relativePath) { return 'Delete'; }
	getUpdatePolicy(relativePath) { return 'Overwrite'; }
	getInstallPolicy(relativePath) { return 'Create'; }
	shouldIgnore(relativePath) { return this.getOwnership(relativePath) === 'User'; }
	isRepositoryManaged(relativePath) { return this.getOwnership(relativePath) !== 'User'; }
}

class InstallationPlanner {
	constructor(plugin) {
		this.plugin = plugin;
		this.resetState();
	}
	
	resetState() {
		this.state = 'idle';
		this.result = null;
	}

	async plan(repoModel, vaultModel, stateModel) {
		this.resetState();
		this.state = 'planning';
		
		console.log("[Planner] Planning started.");
		this.plugin.statusBarItemEl.setText("⏳ GATE: Planning Installation...");
		this.plugin.notifyUI();

		const startTime = Date.now();
		const errors = [];
		const warnings = [];
		
		try {
			if (!repoModel || !repoModel.isValid) throw new Error("Invalid RepositoryModel");
			if (!vaultModel || !vaultModel.isValid) throw new Error("Invalid LocalVaultModel");
			if (!stateModel || !stateModel.isValid) throw new Error("Invalid StateModel");

			const ruleEngine = new RuleEngine(repoModel.rules);
			const unsortedActions = [];
			
			const repoMap = new Map();
			
			if (repoModel.index && Array.isArray(repoModel.index.files) && repoModel.index.files.length > 0) {
				for (const f of repoModel.index.files) {
					const p = typeof f === 'object' ? f.path : f;
					const h = typeof f === 'object' ? f.hash : null;
					const s = typeof f === 'object' ? (f.size || 0) : 0; // Grab size for stats
					repoMap.set(p, { path: p, hash: h, size: s });
				}
			} else {
				const archiveRoot = this.plugin.extractionManager.result.archiveRoot;
				if (archiveRoot && fs.existsSync(archiveRoot)) {
					const queue = [''];
					while(queue.length > 0) {
						const relDir = queue.shift();
						const absDir = path.join(archiveRoot, relDir);
						try {
							const items = await fs.promises.readdir(absDir, { withFileTypes: true });
							for (const item of items) {
								if (item.isSymbolicLink()) continue; // Fix: avoid symlink infinite loops
								const itemRelPath = relDir ? `${relDir}/${item.name}` : item.name;
								if (item.name === '.git') continue; 
								
								if (item.isDirectory()) {
									queue.push(itemRelPath);
								} else if (item.isFile()) {
									// Extract file size for accurate generic-mode statistics
									let size = 0;
									try {
										const stat = await fs.promises.stat(path.join(absDir, item.name));
										size = stat.size;
									} catch(e) {}
									repoMap.set(itemRelPath, { path: itemRelPath, hash: null, size }); 
								}
							}
						} catch(err) {
							warnings.push(`Could not read directory in archive: ${relDir}`);
						}
					}
				}
			}

			const localMap = new Map();
			for (const f of vaultModel.files) {
				localMap.set(f.relativePath, f);
			}

			const stateMap = new Map();
			if (stateModel.installedFiles) {
				for (const f of stateModel.installedFiles) {
					stateMap.set(f.path, f);
				}
			}

			const changelogFile = repoModel.manifest.changelog || null;

			for (const [relativePath, repoEntry] of repoMap.entries()) {
				const localEntry = localMap.get(relativePath);
				const stateEntry = stateMap.get(relativePath);
				const ownership = ruleEngine.getOwnership(relativePath);

				let type, priority, reason, extras = {};
				
				const isMandatory = (changelogFile && relativePath === changelogFile);

				// Security mechanism to block the plugin from overwriting its own files
				if (relativePath.startsWith('.obsidian/plugins/gate-manager/')) {
					type = ActionType.IGNORE;
					priority = ActionPriority.IGNORE;
					reason = "Plugin self-protection. Will not overwrite.";
				} else if (!localEntry || !localEntry.exists) {
					type = ActionType.INSTALL;
					priority = ActionPriority.INSTALL;
					reason = "New file from repository.";
					extras = { source: relativePath, destination: relativePath, repositoryHash: repoEntry.hash };
				} else if (ownership === 'User' && !isMandatory) {
					type = ActionType.IGNORE;
					priority = ActionPriority.IGNORE;
					reason = "User-owned content.";
				} else if (ownership === 'Shared' && !isMandatory) {
					type = ActionType.MERGE;
					priority = ActionPriority.MERGE;
					reason = "Shared ownership.";
					extras = { mergeStrategy: ruleEngine.getMergeStrategy(relativePath), repositoryFile: relativePath, localFile: relativePath };
				} else {
					let currentHash = null;
					if (localEntry && localEntry.exists && repoEntry.hash !== null) {
						try {
							const absPath = path.join(vaultModel.vaultRoot, relativePath);
							currentHash = await HashService.getFileHash(absPath);
						} catch (err) {
							warnings.push(`Failed to hash local file: ${relativePath}`);
						}
					}

					const repoHash = repoEntry.hash;
					const installedHash = stateEntry ? stateEntry.installedHash : null;

					// FIX: Deterministic and safe hash comparisons, correcting first-install & generic mode ambiguity
					if (repoHash === null) {
						// Generic Mode: No repo hash available. Safely skip to prevent overwriting user modifications.
						type = ActionType.SKIP;
						priority = ActionPriority.SKIP;
						reason = "File exists locally but repository lacks hash (Generic Mode). Safely skipping.";
					} else if (installedHash === null) {
						// Unknown State / Pre-existing file before plugin managed it
						if (currentHash === repoHash) {
							type = ActionType.SKIP;
							priority = ActionPriority.SKIP;
							reason = "Existing file matches repository exactly.";
						} else {
							type = ActionType.CONFLICT;
							priority = ActionPriority.CONFLICT;
							reason = "Pre-existing file differs from repository (Unknown origin).";
							extras = { repositoryHash: repoHash, currentHash: currentHash, resolution: 'UNRESOLVED' };
						}
					} else {
						// Known State: Plugin has historically managed this file
						if (currentHash === installedHash) {
							// User has not modified the file
							if (repoHash === installedHash) {
								type = ActionType.SKIP;
								priority = ActionPriority.SKIP;
								reason = "Repository unchanged.";
							} else {
								type = ActionType.UPDATE;
								priority = ActionPriority.UPDATE;
								reason = "Repository updated.";
								extras = { oldHash: installedHash, newHash: repoHash, destination: relativePath };
							}
						} else {
							// User HAS modified the file
							if (repoHash === installedHash) {
								type = ActionType.SKIP;
								priority = ActionPriority.SKIP;
								reason = "Local file modified but repository unchanged. Preserving local edits.";
							} else {
								// Repository updated AND user modified
								if (currentHash === repoHash) {
									type = ActionType.SKIP;
									priority = ActionPriority.SKIP;
									reason = "Local file manually updated to exact new repository state.";
								} else {
									type = ActionType.CONFLICT;
									priority = ActionPriority.CONFLICT;
									reason = "Local file modified and repository updated.";
									extras = { repositoryHash: repoHash, installedHash: installedHash, currentHash: currentHash, resolution: 'UNRESOLVED' };
								}
							}
						}
					}
				}

				// Safety enforcement: If it's the changelog (or mandatory) and missing, force install.
				// However, if there's a CONFLICT, it remains a CONFLICT instead of blindly bypassing safety rules.
				if (isMandatory && type === ActionType.SKIP && (!localEntry || !localEntry.exists)) {
					type = ActionType.INSTALL;
					priority = ActionPriority.INSTALL;
					reason = "Mandatory file missing. Installing.";
				}

				unsortedActions.push(new Action({
					type,
					path: relativePath,
					priority,
					reason,
					isMandatory,
					repositoryEntry: repoEntry,
					localEntry,
					stateEntry,
					estimatedBytes: repoEntry.size || 0,
					...extras
				}));
			}

			for (const [relativePath, stateEntry] of stateMap.entries()) {
				if (!repoMap.has(relativePath)) {
					const localEntry = localMap.get(relativePath);
					if (localEntry && localEntry.exists && !relativePath.startsWith('.obsidian/plugins/gate-manager/')) {
						unsortedActions.push(new Action({
							type: ActionType.ARCHIVE,
							path: relativePath,
							priority: ActionPriority.ARCHIVE,
							reason: "Repository removed file.",
							stateEntry,
							localEntry,
							archiveDestination: relativePath + '.archive',
							removedVersion: repoModel.repositoryVersion
						}));
					}
				}
			}

			unsortedActions.sort((a, b) => {
				if (a.priority !== b.priority) return a.priority - b.priority;
				if (a.path < b.path) return -1;
				if (a.path > b.path) return 1;
				return 0;
			});

			// Fix: Track valid sizes for BytesToInstall and BytesToUpdate
			let bytesToInstall = 0;
			let bytesToUpdate = 0;
			let largestInstall = 0;
			let largestUpdate = 0;

			const actions = [];
			let actionCounter = 1;
			for (const a of unsortedActions) {
				a.id = `ACT-${String(actionCounter++).padStart(6, '0')}`;
				
				if (a.type === ActionType.INSTALL) {
					bytesToInstall += a.estimatedBytes || 0;
					if ((a.estimatedBytes || 0) > largestInstall) largestInstall = a.estimatedBytes || 0;
				} else if (a.type === ActionType.UPDATE) {
					bytesToUpdate += a.estimatedBytes || 0;
					if ((a.estimatedBytes || 0) > largestUpdate) largestUpdate = a.estimatedBytes || 0;
				}

				Object.freeze(a);
				actions.push(a);
			}

			const actionCounts = {
				[ActionType.INSTALL]: 0,
				[ActionType.UPDATE]: 0,
				[ActionType.CONFLICT]: 0,
				[ActionType.MERGE]: 0,
				[ActionType.ARCHIVE]: 0,
				[ActionType.IGNORE]: 0,
				[ActionType.SKIP]: 0
			};
			
			const seenIds = new Set();
			let validationIsValid = true;
			for (const a of actions) {
				actionCounts[a.type] = (actionCounts[a.type] || 0) + 1;
				if (seenIds.has(a.id)) {
					errors.push(`Duplicate Action ID: ${a.id}`);
					validationIsValid = false;
				}
				seenIds.add(a.id);
			}
			
			const summary = {
				TotalActions: actions.length,
				InstallCount: actionCounts[ActionType.INSTALL],
				UpdateCount: actionCounts[ActionType.UPDATE],
				ConflictCount: actionCounts[ActionType.CONFLICT],
				MergeCount: actionCounts[ActionType.MERGE],
				ArchiveCount: actionCounts[ActionType.ARCHIVE],
				IgnoreCount: actionCounts[ActionType.IGNORE],
				SkipCount: actionCounts[ActionType.SKIP],
				ManagedFiles: actions.length,
				RepositoryFiles: repoMap.size,
				VaultFiles: localMap.size
			};

			const duration = Date.now() - startTime;
			
			const stats = {
				PlanningDuration: duration,
				BytesToInstall: bytesToInstall,
				BytesToUpdate: bytesToUpdate,
				LargestInstall: largestInstall,
				LargestUpdate: largestUpdate,
				RepositoryEntryCount: repoMap.size,
				VaultEntryCount: localMap.size,
				ManagedEntryCount: actions.length
			};

			const planValidation = { isValid: validationIsValid, warnings: [...warnings], errors: [...errors] };
			const installPlan = new InstallPlan(actions, summary, stats, planValidation);
			const resultValidation = { isValid: validationIsValid, warnings: [...warnings], errors: [...errors] };

			this.result = new PlanningResult(repoModel, vaultModel, stateModel, installPlan, summary, stats, resultValidation, duration);
			this.state = 'completed';

			console.log("[Planner] Planning complete.");
			this.plugin.statusBarItemEl.setText("✅ GATE: Plan Ready");
			this.plugin.notifyUI();

		} catch (error) {
			console.error("[Planner] Planning failed:", error);
			this.state = 'failed';
			errors.push(error.message);
			const validation = { isValid: false, errors: [...errors], warnings: [...warnings] };
			this.result = new PlanningResult(repoModel, vaultModel, stateModel, null, {}, {}, validation, Date.now() - startTime);
			this.plugin.statusBarItemEl.setText("❌ GATE: Planning Failed");
			this.plugin.notifyUI();
		}
	}
}

class StateMigrator {
	migrate(rawData, currentPluginVersion) {
		// 3. Detect corrupted state: prevent null/undefined from crashing the migrator
		let data = (rawData && typeof rawData === 'object') ? JSON.parse(JSON.stringify(rawData)) : {};

		// 4. Preserve backward compatibility: Handle legacy flat structure
		if (!data.stateVersion && data.installedFiles) {
			data.stateVersion = 1;
		}

		// 1. Proper version migration
		if (!data.stateVersion) data.stateVersion = 1;
		
		// Set defaults for missing fields
		if (!data.pluginVersion) data.pluginVersion = currentPluginVersion;
		if (!data.installedRepository) data.installedRepository = "None";
		if (!data.installedVersion) data.installedVersion = "None";
		if (!data.installationType) data.installationType = "None";
		if (!data.history) data.history = {};
		if (!data.statistics) data.statistics = {};

		if (!Array.isArray(data.installedFiles)) {
			data.installedFiles = [];
		}

		// 5. Prevent duplicate installed entries
		const uniqueFiles = new Map();
		for (const file of data.installedFiles) {
			if (file && typeof file === 'object' && typeof file.path === 'string') {
				// Later entries override earlier ones to keep the most recent state
				uniqueFiles.set(file.path, file);
			}
		}
		data.installedFiles = Array.from(uniqueFiles.values());

		// 6. Validate statistics consistency (Auto-repair during migration)
		data.statistics.installedFiles = data.installedFiles.length;

		// Ensure all statistics fields are present and valid numbers
		if (typeof data.statistics.mergedFiles !== 'number') data.statistics.mergedFiles = 0;
		if (typeof data.statistics.ignoredFiles !== 'number') data.statistics.ignoredFiles = 0;
		if (typeof data.statistics.archivedFiles !== 'number') data.statistics.archivedFiles = 0;
		if (typeof data.statistics.conflicts !== 'number') data.statistics.conflicts = 0;
		if (typeof data.statistics.lastPlanningDuration !== 'number') data.statistics.lastPlanningDuration = 0;

		return data;
	}
}

class StateValidator {
	validate(state, initialErrors = []) {
		const result = { isValid: true, errors: [...initialErrors], warnings: [] };
		
		// 3. Detect corrupted state
		if (!state || typeof state !== 'object') {
			result.errors.push("State object is null or severely corrupted.");
			result.isValid = false;
			return result;
		} 
		
		// 2. State validation
		if (typeof state.stateVersion !== 'number' || state.stateVersion < 1) {
			result.errors.push("Invalid or missing state version.");
		}
		
		if (!Array.isArray(state.installedFiles)) {
			result.errors.push("'installedFiles' must be an array.");
		} else {
			const seenPaths = new Set();
			for (const file of state.installedFiles) {
				if (!file || typeof file !== 'object') {
					result.errors.push("Invalid file entry format detected in state.");
					continue;
				}
				if (!file.path || typeof file.path !== 'string') { 
					result.errors.push("Installed file entry is missing a valid 'path'."); 
					continue; 
				}
				if (seenPaths.has(file.path)) {
					// 5. Catch any duplicates that bypassed migration
					result.errors.push(`Duplicate file entry in state: ${file.path}`);
				}
				seenPaths.add(file.path);
			}
		}
		
		if (typeof state.history !== 'object' || state.history === null) {
			result.errors.push("'history' must be a valid object.");
		}
		if (typeof state.statistics !== 'object' || state.statistics === null) {
			result.errors.push("'statistics' must be a valid object.");
		} else if (state.installedFiles && state.statistics.installedFiles !== state.installedFiles.length) {
			// 6. Validate statistics consistency
			result.warnings.push("Statistics mismatch: 'installedFiles' count does not match the actual array length.");
		}
		
		if (result.errors.length > 0) result.isValid = false;
		return result;
	}
}

class StateModel {
	constructor(data, validation) {
		// `data` may legitimately be `{}` (e.g. the error-recovery path in StateLoader.load()
		// calls `new StateModel({}, validation)`), so every nested field must be defaulted
		// defensively rather than dereferenced directly — otherwise the recovery path itself
		// throws, and the plugin never reaches a clean "invalid state" UI.
		data = data || {};
		const statistics = data.statistics || {};
		const history = data.history || {};
		const installedFiles = Array.isArray(data.installedFiles) ? data.installedFiles : [];

		this.pluginVersion = data.pluginVersion || null;
		this.stateVersion = data.stateVersion || null;
		this.installedRepository = data.installedRepository || null;
		this.installedVersion = data.installedVersion || null;
		this.installationDate = data.installationDate || null;
		this.lastUpdate = data.lastUpdate || null;
		this.lastRestore = data.lastRestore || null;
		this.installationType = data.installationType || null;
		this.statistics = Object.freeze({
			installedFiles: statistics.installedFiles || 0,
			mergedFiles: statistics.mergedFiles || 0,
			ignoredFiles: statistics.ignoredFiles || 0,
			archivedFiles: statistics.archivedFiles || 0,
			conflicts: statistics.conflicts || 0,
			lastPlanningDuration: statistics.lastPlanningDuration || 0
		});
		this.installedFiles = Object.freeze(installedFiles.map(f => Object.freeze({ ...f })));
		this.history = Object.freeze({
			firstInstall: history.firstInstall || null,
			lastInstall: history.lastInstall || null,
			lastUpdate: history.lastUpdate || null,
			lastRestore: history.lastRestore || null
		});
		this.validation = Object.freeze(validation || { isValid: false, errors: ['No validation result provided.'], warnings: [] });
		this.errors = this.validation.errors || [];
		this.warnings = this.validation.warnings || [];
		this.isValid = !!this.validation.isValid;
		Object.freeze(this);
	}
}

class StateLoader {
	constructor(plugin) {
		this.plugin = plugin;
		this.resetState();
	}
	
	resetState() {
		this.state = 'idle';
		this.model = null;
	}
	
	async load() {
		this.resetState();
		this.state = 'loading';
		console.log("[GATE Manager] Loading Plugin State...");
		if (this.plugin.statusBarItemEl) {
			this.plugin.statusBarItemEl.setText("⏳ GATE: Loading Plugin State...");
		}
		this.plugin.notifyUI();

		try {
			const loadedData = await this.plugin.loadData() || {};
			
			// 4. Preserve backward compatibility by checking where state is stored
			let rawStateData = {};
			if (loadedData.state) {
				rawStateData = loadedData.state;
			} else {
				// Legacy structure: state keys were placed directly at the root level alongside settings
				rawStateData = { ...loadedData };
				delete rawStateData.settings; // Ensure settings are excluded from state object
			}

			const migrator = new StateMigrator();
			const migratedData = migrator.migrate(rawStateData, this.plugin.manifest.version);
			
			const validator = new StateValidator();
			const validation = validator.validate(migratedData);

			this.model = new StateModel(migratedData, validation);
			this.state = 'completed';

			if (this.model.isValid) {
				console.log("[GATE Manager] Plugin state loaded successfully.");
				if (this.plugin.statusBarItemEl) this.plugin.statusBarItemEl.setText("✅ GATE: State Ready");
				this.plugin.vaultStatus.installedVersion = this.model.installedVersion !== "None" ? this.model.installedVersion : null;
				this.plugin.vaultStatus.isInstalled = !!this.plugin.vaultStatus.installedVersion;
			} else {
				console.warn("[GATE Manager] Plugin state validation failed.", this.model.errors);
				if (this.plugin.statusBarItemEl) this.plugin.statusBarItemEl.setText("❌ GATE: State Invalid");
			}
			this.plugin.notifyUI();
		} catch (error) {
			console.error("[GATE Manager] State Loader Exception:", error);
			this.state = 'failed';
			const validation = { isValid: false, errors: [error.message], warnings: [] };
			this.model = new StateModel({}, validation);
			if (this.plugin.statusBarItemEl) this.plugin.statusBarItemEl.setText("❌ GATE: State Invalid");
			this.plugin.notifyUI();
		}
	}
}

class HashService {
	// Fix: Read text files to normalize Windows/Linux CRLF before hashing
	static async getFileHash(absolutePath) {
		if (!fs.existsSync(absolutePath)) throw new Error("File does not exist.");
		const hash = crypto.createHash('sha256');
		const ext = path.extname(absolutePath).toLowerCase();
		const textExts = ['.md', '.txt', '.json', '.csv', '.js', '.css', '.html', '.xml', '.yaml', '.yml', '.svg'];

		if (textExts.includes(ext)) {
			let content = await fs.promises.readFile(absolutePath, 'utf8');
			content = content.replace(/\r\n/g, '\n');
			hash.update(content, 'utf8');
			return hash.digest('hex');
		} else {
			return new Promise((resolve, reject) => {
				const stream = fs.createReadStream(absolutePath);
				stream.on('data', data => hash.update(data));
				stream.on('end', () => resolve(hash.digest('hex')));
				stream.on('error', err => reject(err));
			});
		}
	}
}

class FileScanner {
	static async scanAsync(rootPath, relativePath) {
		const absolutePath = path.join(rootPath, relativePath);
		const normalizedRel = relativePath.replace(/\\/g, '/');
		try {
			const stats = await fs.promises.stat(absolutePath);
			const ext = path.extname(normalizedRel).toLowerCase();
			const isMarkdown = ext === '.md';
			const textExts = ['.md', '.txt', '.json', '.csv', '.js', '.css', '.html', '.xml', '.yaml', '.yml', '.svg'];
			const isBinary = !textExts.includes(ext);
			return Object.freeze({ relativePath: normalizedRel, extension: ext, size: stats.size, modifiedTime: stats.mtimeMs, exists: true, isMarkdown, isBinary });
		} catch (err) {
			return Object.freeze({ relativePath: normalizedRel, exists: false, error: err.message });
		}
	}
}

class DirectoryScanner {
	static scan(rootPath, relativePath, childrenCount = 0) {
		const normalizedRel = relativePath.replace(/\\/g, '/');
		try {
			// Fix: Force POSIX directory name to keep forward slash format intact
			let parent = path.posix.dirname(normalizedRel);
			if (parent === '.' || parent === normalizedRel) parent = '';
			const depth = normalizedRel === '' ? 0 : normalizedRel.split('/').length;
			return Object.freeze({ relativePath: normalizedRel, parent, depth, childrenCount, exists: true });
		} catch (err) {
			return Object.freeze({ relativePath: normalizedRel, exists: false, error: err.message });
		}
	}
}

class VaultValidator {
	validate(directories, files, initialErrors = []) {
		const result = { isValid: true, errors: [...initialErrors], warnings: [] };
		const seenPaths = new Set();
		for (const d of directories) {
			if (seenPaths.has(d.relativePath)) result.errors.push(`Duplicate path detected: ${d.relativePath}`);
			seenPaths.add(d.relativePath);
			if (!d.exists) result.warnings.push(`Unreadable directory: ${d.relativePath}`);
		}
		for (const f of files) {
			if (seenPaths.has(f.relativePath)) result.errors.push(`Duplicate path detected: ${f.relativePath}`);
			seenPaths.add(f.relativePath);
			if (!f.exists) result.errors.push(`Unreadable file: ${f.relativePath}`);
		}
		if (result.errors.length > 0) result.isValid = false;
		return Object.freeze(result);
	}
}

class LocalVaultModel {
	constructor(vaultRoot, directories, files, statistics, validation) {
		this.vaultRoot = vaultRoot;
		this.directories = Object.freeze([...directories]);
		this.files = Object.freeze([...files]);
		this.statistics = Object.freeze(statistics);
		this.validation = Object.freeze(validation);
		this.errors = this.validation.errors;
		this.warnings = this.validation.warnings;
		this.isValid = this.validation.isValid;
		Object.freeze(this);
	}
}

class VaultScanner {
	constructor(plugin) { this.plugin = plugin; this.resetState(); }
	resetState() { this.state = 'idle'; this.model = null; }

	async scan() {
		this.resetState();
		this.state = 'scanning';
		console.log("[GATE Manager] Starting Local Vault Scan...");
		this.plugin.statusBarItemEl.setText("🔄 GATE: Scanning Vault...");
		this.plugin.notifyUI();

		try {
			const vaultRoot = this.plugin.app.vault.adapter.getBasePath();
			const validator = new VaultValidator();
			const directoriesMap = new Map();
			const files = [];
			const errors = [];
			const queue = ['']; 
			let rootDirChildren = 0; // childrenCount for the vault root itself (currentRelPath === '')
			
			// Fix: Make directory reads non-blocking asynchronous calls
			while (queue.length > 0) {
				const currentRelPath = queue.shift();
				const currentAbsPath = path.join(vaultRoot, currentRelPath);
				try {
					const items = await fs.promises.readdir(currentAbsPath, { withFileTypes: true });
					let childrenCount = 0;
					
					const filePromises = [];
					for (const item of items) {
						if (item.isSymbolicLink()) continue; // Fix: Prevent traversing infinite symlinks

						const itemRelPath = currentRelPath ? path.join(currentRelPath, item.name) : item.name;
						const normalizedItemRel = itemRelPath.replace(/\\/g, '/');
						if (normalizedItemRel.startsWith('.obsidian/plugins/gate-manager/cache')) continue;
						
						childrenCount++;
						if (item.isDirectory()) {
							queue.push(itemRelPath);
							directoriesMap.set(normalizedItemRel, { path: itemRelPath, childrenCount: 0 });
						} else if (item.isFile()) {
							filePromises.push(FileScanner.scanAsync(vaultRoot, itemRelPath));
						} else {
							files.push(Object.freeze({ relativePath: normalizedItemRel, exists: false, error: 'Unsupported file type' }));
						}
					}
					// Parallel non-blocking stats for files in current dir
					const scannedFiles = await Promise.all(filePromises);
					files.push(...scannedFiles);

					if (currentRelPath !== '') {
						const normalizedCurrent = currentRelPath.replace(/\\/g, '/');
						const dirData = directoriesMap.get(normalizedCurrent);
						if (dirData) dirData.childrenCount = childrenCount;
					} else {
						// This is the vault root's own scan pass — record its childrenCount
						// directly. Previously this count was computed but then discarded
						// (only non-root paths were written into directoriesMap), and the
						// root's childrenCount was reconstructed afterwards by grabbing
						// whichever directory happened to be inserted first into the Map —
						// i.e. an essentially arbitrary subdirectory, not the root at all.
						rootDirChildren = childrenCount;
					}
				} catch (err) {
					errors.push(`Unreadable directory: ${currentRelPath} (${err.message})`);
				}
			}

			const directories = [DirectoryScanner.scan(vaultRoot, '', rootDirChildren)];
			for (const [normalizedPath, data] of directoriesMap.entries()) {
				directories.push(DirectoryScanner.scan(vaultRoot, data.path, data.childrenCount));
			}

			let markdownFiles = 0, binaryFiles = 0, totalBytes = 0, largestFile = null, deepestFolder = null;
			for (const f of files) {
				if (f.exists && !f.error) {
					if (f.isMarkdown) markdownFiles++;
					if (f.isBinary) binaryFiles++;
					totalBytes += f.size;
					if (!largestFile || f.size > largestFile.size) largestFile = f;
				}
			}
			for (const d of directories) {
				if (d.exists && !d.error) {
					if (!deepestFolder || d.depth > deepestFolder.depth) deepestFolder = d;
				}
			}

			const statistics = { totalFiles: files.length, totalDirectories: directories.length, markdownFiles, binaryFiles, totalBytes, largestFile: largestFile ? largestFile.relativePath : null, deepestFolder: deepestFolder ? deepestFolder.relativePath : null };
			const validation = validator.validate(directories, files, errors);
			this.model = new LocalVaultModel(vaultRoot, directories, files, statistics, validation);
			this.state = 'completed';

			console.log("[GATE Manager] Vault Scan Complete.");
			this.plugin.statusBarItemEl.setText("✅ GATE: Vault Ready");
			this.plugin.notifyUI();
		} catch (err) {
			this.state = 'failed';
			console.error("[GATE Manager] Vault Scan Failed", err);
			this.plugin.statusBarItemEl.setText("❌ GATE: Vault Scan Failed");
			this.plugin.notifyUI();
		}
	}
}

class ManifestReader {
	read(archiveRoot, errors) {
		const target = path.join(archiveRoot, 'vault-manifest.json');
		if (!fs.existsSync(target)) return null;
		try { return JSON.parse(fs.readFileSync(target, 'utf8')); } catch (e) { errors.push("vault-manifest.json contains invalid JSON."); return null; }
	}
}

class RulesReader {
	read(archiveRoot, errors) {
		const target = path.join(archiveRoot, 'vault-rules.json');
		if (!fs.existsSync(target)) return null;
		try { return JSON.parse(fs.readFileSync(target, 'utf8')); } catch (e) { errors.push("vault-rules.json contains invalid JSON."); return null; }
	}
}

class IndexReader {
	read(archiveRoot, errors) {
		const target = path.join(archiveRoot, 'vault-index.json');
		if (!fs.existsSync(target)) return null;
		try { return JSON.parse(fs.readFileSync(target, 'utf8')); } catch (e) { errors.push("vault-index.json contains invalid JSON."); return null; }
	}
}

class RepositoryValidator {
	validate(manifest, rules, index, initialErrors = []) {
		const result = { isValid: true, errors: [...initialErrors], warnings: [] };

		if (!manifest) {
			result.warnings.push("Missing vault-manifest.json (Running in Generic Mode)");
		} else {
			if (!manifest.id) result.errors.push("Manifest missing 'id'");
			if (!manifest.version) result.errors.push("Manifest missing 'version'");
			if (!manifest.repository || !manifest.repository.owner) result.errors.push("Manifest missing 'repository.owner'");
		}

		if (!rules) {
			result.warnings.push("Missing vault-rules.json");
		} else {
			if (typeof rules !== 'object' || Array.isArray(rules)) {
				result.errors.push("vault-rules.json must be a JSON object");
			} else {
				if (rules.ownership && typeof rules.ownership !== 'string') result.errors.push("Invalid 'ownership' format in vault-rules.json");
				if (rules.mergeStrategy && typeof rules.mergeStrategy !== 'string') result.errors.push("Invalid 'mergeStrategy' format in vault-rules.json");
			}
		}

		if (!index) {
			result.warnings.push("Missing vault-index.json");
		} else {
			if (typeof index !== 'object' || Array.isArray(index)) {
				result.errors.push("vault-index.json must be a JSON object");
			}
		}

		if (result.errors.length > 0) result.isValid = false;
		return result;
	}
}

class RepositoryModel {
	constructor(manifest, rules, index, validation) {
		this.manifest = manifest || {};
		this.rules = rules || {};
		this.index = index || {};
		this.dependencies = this.manifest.dependencies || { plugins: [], themes: [] };
		
		this.repositoryName = this.manifest.repository && this.manifest.repository.name ? this.manifest.repository.name : "Unknown";
		this.repositoryOwner = this.manifest.repository && this.manifest.repository.owner ? this.manifest.repository.owner : "Unknown";
		this.repositoryVersion = this.manifest.version ? this.manifest.version : "Unknown";
		this.validation = validation;
		this.isValid = validation.isValid;
		this.errors = validation.errors;
		this.warnings = validation.warnings;

		let ruleCount = 0;
		if (rules && typeof rules === 'object' && !Array.isArray(rules)) {
			if (Array.isArray(rules.rules)) ruleCount = rules.rules.length;
			else ruleCount = Object.keys(rules).length;
		}

		let indexedFiles = 0;
		if (index && index.files) {
			if (Array.isArray(index.files)) indexedFiles = index.files.length;
			else if (typeof index.files === 'object') indexedFiles = Object.keys(index.files).length;
		}

		this.statistics = Object.freeze({ ruleCount, indexedFiles });
		Object.freeze(this.validation);
		Object.freeze(this);
	}
}

class RepositoryModelLoader {
	constructor(plugin) { this.plugin = plugin; this.resetState(); }
	resetState() { this.state = 'idle'; this.model = null; }

	async load(archiveRoot) {
		this.resetState();
		this.state = 'loading';
		console.log(`[GATE Manager] Loading Repository Model from: ${archiveRoot}`);
		this.plugin.statusBarItemEl.setText("⏳ GATE: Loading Repository...");
		this.plugin.notifyUI();

		try {
			const errors = [];
			const manifestReader = new ManifestReader();
			const rulesReader = new RulesReader();
			const indexReader = new IndexReader();

			const manifest = manifestReader.read(archiveRoot, errors);
			const rules = rulesReader.read(archiveRoot, errors);
			const index = indexReader.read(archiveRoot, errors);

			this.state = 'validating';
			this.plugin.statusBarItemEl.setText("⏳ GATE: Validating Repository...");
			this.plugin.notifyUI();

			const validator = new RepositoryValidator();
			const validation = validator.validate(manifest, rules, index, errors);
			this.model = new RepositoryModel(manifest, rules, index, validation);
			this.state = 'completed';

			if (this.model.isValid) {
				console.log("[GATE Manager] Repository validation completed successfully.");
				this.plugin.statusBarItemEl.setText("✅ GATE: Repository Ready");
			} else {
				console.warn("[GATE Manager] Repository validation failed.", this.model.errors);
				this.plugin.statusBarItemEl.setText("❌ GATE: Repository Invalid");
			}
			this.plugin.notifyUI();
		} catch (error) {
			console.error("[GATE Manager] Repository Loader Exception:", error);
			this.state = 'failed';
			const validation = { isValid: false, errors: [error.message], warnings: [] };
			this.model = new RepositoryModel(null, null, null, validation);
			this.plugin.statusBarItemEl.setText("❌ GATE: Repository Invalid");
			this.plugin.notifyUI();
		}
	}
}

class TempDirectoryManager {
	constructor(plugin) { this.plugin = plugin; }
	getCacheDir() { return path.join(this.plugin.app.vault.adapter.getBasePath(), this.plugin.manifest.dir, 'cache'); }
	getArchivePath() { return path.join(this.getCacheDir(), 'download.zip'); }
	getExtractedDir() { return path.join(this.getCacheDir(), 'extracted'); }
	
	async prepareCache() {
		const cacheDir = this.getCacheDir();
		if (!fs.existsSync(cacheDir)) {
			await fs.promises.mkdir(cacheDir, { recursive: true });
		}
	}
	
	async cleanExtracted() {
		const extractedDir = this.getExtractedDir();
		if (fs.existsSync(extractedDir)) {
			try {
				await fs.promises.rm(extractedDir, { recursive: true, force: true });
			} catch (e) {
				console.warn("[GATE Manager] Could not delete extracted dir (possibly locked):", e);
			}
		}
	}
	
	async createExtracted() {
		await this.cleanExtracted();
		await fs.promises.mkdir(this.getExtractedDir(), { recursive: true });
	}
	
	async cleanAll() {
		const cacheDir = this.getCacheDir();
		if (fs.existsSync(cacheDir)) {
			try {
				await fs.promises.rm(cacheDir, { recursive: true, force: true });
			} catch (e) {
				console.warn("[GATE Manager] Could not fully delete cache dir (possibly locked):", e);
			}
		}
	}
}

class ArchiveReader {
	constructor(filePath) { this.filePath = filePath; }

	readCentralDirectory() {
		const stats = fs.statSync(this.filePath);
		if (stats.size === 0) throw new Error("Archive file is empty.");
		
		// Fix: Improved corrupted ZIP recovery & safely detecting malformed archives
		let fd = null;
		try {
			fd = fs.openSync(this.filePath, 'r');
			const searchSize = Math.min(stats.size, 65557);
			const buffer = Buffer.alloc(searchSize);
			fs.readSync(fd, buffer, 0, searchSize, stats.size - searchSize);

			let eocdOffset = -1;
			for (let i = buffer.length - 22; i >= 0; i--) {
				if (buffer.readUInt32LE(i) === 0x06054b50) { eocdOffset = i; break; }
			}
			if (eocdOffset === -1) throw new Error("Not a valid ZIP file (EOCD Signature missing).");

			if (eocdOffset + 22 > buffer.length) throw new Error("Malformed archive: EOCD record truncated.");

			const cdEntries = buffer.readUInt16LE(eocdOffset + 10);
			const cdSize = buffer.readUInt32LE(eocdOffset + 12);
			const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

			if (cdOffset + cdSize > stats.size) {
				throw new Error("Malformed archive: Central Directory is out of bounds (corrupted data).");
			}

			const cdBuffer = Buffer.alloc(cdSize);
			fs.readSync(fd, cdBuffer, 0, cdSize, cdOffset);

			const entries = [];
			let offset = 0;
			for (let i = 0; i < cdEntries; i++) {
				if (offset + 46 > cdBuffer.length) {
					throw new Error("Malformed archive: Central Directory entry overflows buffer.");
				}
				if (cdBuffer.readUInt32LE(offset) !== 0x02014b50) {
					throw new Error("Malformed archive: Invalid Central Directory signature.");
				}

				const compMethod = cdBuffer.readUInt16LE(offset + 10);
				const compSize = cdBuffer.readUInt32LE(offset + 20);
				const uncompSize = cdBuffer.readUInt32LE(offset + 24);
				const nameLen = cdBuffer.readUInt16LE(offset + 28);
				const extraLen = cdBuffer.readUInt16LE(offset + 30);
				const commentLen = cdBuffer.readUInt16LE(offset + 32);
				const localHeaderOffset = cdBuffer.readUInt32LE(offset + 42);

				if (offset + 46 + nameLen + extraLen + commentLen > cdBuffer.length) {
					throw new Error("Malformed archive: Entry header exceeds Central Directory boundary.");
				}

				const name = cdBuffer.toString('utf8', offset + 46, offset + 46 + nameLen);
				
				// Fix: ZIP bomb & Directory Traversal protection
				if (name.includes('../') || name.includes('..\\') || name.startsWith('/') || name.startsWith('\\') || name.includes('\0')) {
					throw new Error(`Security Exception: Path traversal attempt detected in archive entry: ${name}`);
				}

				entries.push({ name, compMethod, compSize, uncompSize, localHeaderOffset });
				offset += 46 + nameLen + extraLen + commentLen;
			}
			return entries;
		} finally {
			if (fd !== null) fs.closeSync(fd);
		}
	}

	extractFileToMemory(entry) {
		const stats = fs.statSync(this.filePath);
		let fd = null;
		try {
			fd = fs.openSync(this.filePath, 'r');
			if (entry.localHeaderOffset + 30 > stats.size) {
				throw new Error("Malformed archive: Local File Header out of bounds.");
			}

			const headerBuffer = Buffer.alloc(30);
			fs.readSync(fd, headerBuffer, 0, 30, entry.localHeaderOffset);
			if (headerBuffer.readUInt32LE(0) !== 0x04034b50) throw new Error("Archive is corrupted (Invalid Local File Header signature).");

			const nameLen = headerBuffer.readUInt16LE(26);
			const extraLen = headerBuffer.readUInt16LE(28);
			const dataOffset = entry.localHeaderOffset + 30 + nameLen + extraLen;
			
			if (dataOffset + entry.compSize > stats.size) {
				throw new Error("Malformed archive: Compressed file data exceeds archive boundary.");
			}

			const dataBuffer = Buffer.alloc(entry.compSize);
			fs.readSync(fd, dataBuffer, 0, entry.compSize, dataOffset);

			if (entry.compMethod === 0) return dataBuffer;
			else if (entry.compMethod === 8) return zlib.inflateRawSync(dataBuffer);
			else throw new Error(`Unsupported compression method: ${entry.compMethod}`);
		} catch (err) {
			throw new Error(`Memory extraction failed for ${entry.name}: ${err.message}`);
		} finally {
			if (fd !== null) fs.closeSync(fd);
		}
	}

	extractFileToDisk(entry, destPath) {
		return new Promise((resolve, reject) => {
			let fd = null;
			try {
				const stats = fs.statSync(this.filePath);
				fd = fs.openSync(this.filePath, 'r');
				
				if (entry.localHeaderOffset + 30 > stats.size) {
					throw new Error("Malformed archive: Local File Header out of bounds.");
				}

				const headerBuffer = Buffer.alloc(30);
				fs.readSync(fd, headerBuffer, 0, 30, entry.localHeaderOffset);
				if (headerBuffer.readUInt32LE(0) !== 0x04034b50) throw new Error("Archive is corrupted (Invalid Local File Header signature).");

				const nameLen = headerBuffer.readUInt16LE(26);
				const extraLen = headerBuffer.readUInt16LE(28);
				const dataOffset = entry.localHeaderOffset + 30 + nameLen + extraLen;
				
				if (dataOffset + entry.compSize > stats.size) {
					throw new Error("Malformed archive: Compressed file data exceeds archive boundary.");
				}

				fs.closeSync(fd);
				fd = null;

				if (entry.compSize === 0) {
					if (entry.uncompSize !== 0) throw new Error(`Malformed archive: entry ${entry.name} has no compressed data but uncompressed size is > 0.`);
					fs.writeFileSync(destPath, '');
					return resolve({ actualSize: 0, hash: crypto.createHash('sha256').digest('hex') });
				}

				const readStream = fs.createReadStream(this.filePath, { start: dataOffset, end: dataOffset + entry.compSize - 1 });
				const writeStream = fs.createWriteStream(destPath);
				
				// Fix: Compute hash and actual size during stream for integrity verification
				const hasher = crypto.createHash('sha256');
				let actualSize = 0;

				const dataHandler = (chunk) => {
					actualSize += chunk.length;
					hasher.update(chunk);
				};
				
				const cleanup = (err) => {
					readStream.destroy();
					writeStream.destroy();
					reject(new Error(`Disk extraction failed for ${entry.name}: ${err.message}`));
				};

				readStream.on('error', cleanup);
				writeStream.on('error', cleanup);
				
				writeStream.on('finish', () => {
					resolve({ actualSize, hash: hasher.digest('hex') });
				});

				if (entry.compMethod === 0) {
					readStream.on('data', dataHandler);
					readStream.pipe(writeStream);
				}
				else if (entry.compMethod === 8) {
					const inflater = zlib.createInflateRaw();
					inflater.on('error', cleanup);
					inflater.on('data', dataHandler);
					readStream.pipe(inflater).pipe(writeStream);
				} else reject(new Error(`Unsupported compression method: ${entry.compMethod}`));
			} catch (err) {
				if (fd !== null) fs.closeSync(fd);
				reject(new Error(`Extraction initialization failed for ${entry.name}: ${err.message}`));
			}
		});
	}
}

class VaultStatus {
	constructor() {
		this.isInstalled = false;
		this.installedVersion = null; 
		this.repoName = "Unknown";
		this.latestVersion = "Unknown";
		this.latestReleaseDate = "Unknown";
		this.releaseNotes = "";
		this.downloadUrl = null;
		this.connectionStatus = "Offline"; 
		this.authenticated = false; // true when the last successful check used a GitHub token
	}
	get statusText() {
		if (this.connectionStatus !== "Connected") return this.connectionStatus;
		if (!this.isInstalled) return "Not Installed";
		if (VersionUtils.compareVersions(this.latestVersion, this.installedVersion) > 0) return "Update Available";
		return "Latest";
	}
}

class VerificationResult {
	constructor(archivePath) {
		this.state = 'pending';
		this.verified = false;
		this.manifest = null;
		this.errors = [];
		this.warnings = [];
		this.archivePath = archivePath;
		this.archiveSize = 0;
	}
}

class ArchiveVerificationManager {
	constructor(plugin) { this.plugin = plugin; this.result = null; }
	reset() { this.result = null; }

	async verify(archivePath) {
		this.result = new VerificationResult(archivePath);
		this.plugin.statusBarItemEl.setText("⏳ GATE: Verifying...");

		const MAX_FILE_COUNT = 50000;
		const MAX_UNCOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024; // 2GB
		const MAX_COMPRESSION_RATIO = 150;

		try {
			if (!fs.existsSync(archivePath)) throw new Error("Archive missing from disk.");
			const stats = await fs.promises.stat(archivePath);
			if (stats.size === 0) throw new Error("Archive file is empty (0 bytes).");
			this.result.archiveSize = stats.size;

			const zip = new ArchiveReader(archivePath);
			const entries = zip.readCentralDirectory();
			
			// Fix: ZIP bomb protection (verify totals and ratios before extraction)
			let totalUncompSize = 0;
			if (entries.length > MAX_FILE_COUNT) {
				throw new Error(`Security Exception: Archive contains too many files (${entries.length}). Limit is ${MAX_FILE_COUNT}.`);
			}

			for (const entry of entries) {
				totalUncompSize += entry.uncompSize;
				if (entry.compSize > 1024 && (entry.uncompSize / entry.compSize) > MAX_COMPRESSION_RATIO) {
					throw new Error(`Security Exception: Suspicious compression ratio detected in ${entry.name} (ZIP bomb protection).`);
				}
			}

			if (totalUncompSize > MAX_UNCOMPRESSED_SIZE) {
				throw new Error(`Security Exception: Uncompressed payload exceeds maximum safe limit of 2GB.`);
			}
			
			const manifestEntry = entries.find(e => e.name.endsWith('vault-manifest.json'));
			if (manifestEntry) {
				const manifestBuffer = zip.extractFileToMemory(manifestEntry);
				const manifestJson = manifestBuffer.toString('utf8');
				
				try { 
					this.result.manifest = JSON.parse(manifestJson);
					
					if (this.result.manifest.plugin && this.result.manifest.plugin.minimumVersion) {
						if (VersionUtils.compareVersions(this.result.manifest.plugin.minimumVersion, this.plugin.manifest.version) > 0) {
							throw new Error(`Plugin version incompatible. This vault requires GATE Manager version ${this.result.manifest.plugin.minimumVersion} or newer.`);
						}
					}
				} catch(e) { 
					if (e.message.includes('Plugin version incompatible')) throw e;
					this.result.warnings.push("Manifest invalid (contains invalid JSON). Proceeding in generic mode.");
				}
			} else {
				this.result.warnings.push("Manifest missing. Proceeding in generic mode.");
			}

			this.result.verified = true;
			this.result.state = 'verified';

		} catch (error) {
			this.result.state = 'failed';
			this.result.errors.push(error.message);
		}
		return this.result;
	}
}

class ExtractionResult {
	constructor() {
		this.success = false;
		this.archiveRoot = null;
		this.cacheDirectory = null;
		this.manifestPath = null;
		this.totalFiles = 0;
		this.totalDirectories = 0;
		this.totalBytes = 0;
		this.warnings = [];
		this.errors = [];
	}
}

class ExtractionVerifier {
	constructor(plugin) { this.plugin = plugin; }

	// Recursively count regular files under `dir` (directories don't count).
	_countFilesRecursive(dir) {
		let count = 0;
		let entries;
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch (e) {
			return count;
		}
		for (const entry of entries) {
			if (entry.isSymbolicLink()) continue;
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				count += this._countFilesRecursive(full);
			} else if (entry.isFile()) {
				count++;
			}
		}
		return count;
	}
	
	verify(archiveRoot, expectedFileCount) {
		if (!fs.existsSync(archiveRoot)) return false;
		
		try {
			const stats = fs.statSync(archiveRoot);
			if (!stats.isDirectory()) return false;
			
			// Fix: Verify the extraction actually produced (at least) the expected number of
			// files, counted recursively across the whole tree. The previous check only
			// confirmed the top-level directory was non-empty (fs.readdirSync(archiveRoot).length
			// > 0), so an archive that was supposed to contain hundreds of files nested in
			// subfolders, but which silently stopped extracting after just one top-level entry,
			// would still pass. Comparing against a real recursive count catches that.
			if (expectedFileCount > 0) {
				const actualFileCount = this._countFilesRecursive(archiveRoot);
				if (actualFileCount < expectedFileCount) {
					console.error(`[GATE Manager] Extraction verification failed: expected at least ${expectedFileCount} files, found ${actualFileCount}.`);
					return false;
				}
			}
		} catch (e) {
			return false;
		}
		
		return true;
	}
}

class ArchiveExtractionManager {
	constructor(plugin) { this.plugin = plugin; this.resetState(); }
	resetState() {
		this.state = 'idle';
		this.progress = { extractedEntries: 0, totalEntries: 0 };
		this.result = new ExtractionResult();
	}

	async extract(archivePath) {
		this.resetState();
		this.state = 'extracting';
		this.plugin.statusBarItemEl.setText("🔄 GATE: Preparing Extraction...");
		this.plugin.notifyUI();

		const tempManager = this.plugin.tempManager;
		
		try {
			await tempManager.createExtracted();
			const destDir = tempManager.getExtractedDir();
			this.result.cacheDirectory = destDir;

			const reader = new ArchiveReader(archivePath);
			const entries = reader.readCentralDirectory();
			this.progress.totalEntries = entries.length;

			let possibleRoot = null;
			let isSingleRoot = true;
			for (const entry of entries) {
				const parts = entry.name.split('/');
				const topLevel = parts[0];
				
				if (!possibleRoot) {
					possibleRoot = topLevel;
				} else if (possibleRoot !== topLevel) {
					isSingleRoot = false;
					break;
				}
			}
			const rootFolderName = isSingleRoot && possibleRoot ? possibleRoot : "";
			this.result.archiveRoot = rootFolderName ? path.join(destDir, rootFolderName) : destDir;
			this.result.manifestPath = path.join(this.result.archiveRoot, 'vault-manifest.json');

			const extractedFilesMap = new Map(); // Store path -> { size, hash }

			for (let i = 0; i < entries.length; i++) {
				const entry = entries[i];
				const fullPath = path.resolve(destDir, entry.name);
				
				if (!isPathInside(fullPath, destDir)) {
					this.result.warnings.push(`Skipped invalid path (Traversal blocked): ${entry.name}`);
					continue;
				}

				if (entry.name.endsWith('/')) {
					await fs.promises.mkdir(fullPath, { recursive: true });
					this.result.totalDirectories++;
				} else {
					await fs.promises.mkdir(path.dirname(fullPath), { recursive: true });
					
					// Fix: Capture actual extracted size and SHA256 hash
					const extractData = await reader.extractFileToDisk(entry, fullPath);
					
					// Fix: Verify extracted file sizes match internal ZIP metadata precisely
					if (extractData.actualSize !== entry.uncompSize) {
						throw new Error(`Size mismatch for ${entry.name}: expected ${entry.uncompSize} bytes, got ${extractData.actualSize} bytes. Archive is corrupted.`);
					}

					let relPath = entry.name;
					if (rootFolderName && relPath.startsWith(rootFolderName + '/')) {
						relPath = relPath.substring(rootFolderName.length + 1);
					}
					extractedFilesMap.set(relPath, extractData);

					this.result.totalFiles++;
					this.result.totalBytes += entry.uncompSize;
				}

				this.progress.extractedEntries++;
				if (i % 25 === 0) {
					this.plugin.statusBarItemEl.setText(`🔄 GATE: Extracting ${this.progress.extractedEntries}/${this.progress.totalEntries}`);
					this.plugin.notifyUI();
				}
			}

			this.state = 'verifying';
			this.plugin.statusBarItemEl.setText("⏳ GATE: Verifying Extraction...");
			this.plugin.notifyUI();

			const verifier = new ExtractionVerifier(this.plugin);
			if (!verifier.verify(this.result.archiveRoot, this.result.totalFiles)) {
				throw new Error("Extraction verification failed: output directory is empty or missing.");
			}

			// Fix: Verify extracted hashes securely if vault-index.json is available
			const indexPath = path.join(this.result.archiveRoot, 'vault-index.json');
			if (fs.existsSync(indexPath)) {
				let indexData;
				try {
					indexData = JSON.parse(await fs.promises.readFile(indexPath, 'utf8'));
				} catch (e) {
					// Fail closed: shipping vault-index.json means this repo opts into
					// index-based integrity verification. If it can't be read or parsed, there
					// is no way to confirm the extracted files match what the repo actually
					// published — previously this only logged a warning and let installation
					// proceed anyway, which defeats the purpose of shipping an index at all (a
					// tampered or truncated release could ship a broken index specifically to
					// bypass this check). Abort the whole extraction instead of continuing.
					throw new Error(`Extraction verification failed: vault-index.json exists but could not be read or parsed (${e.message}). Aborting rather than installing unverified content.`);
				}

				if (indexData && Array.isArray(indexData.files)) {
					for (const f of indexData.files) {
						if (typeof f === 'object' && f.path && f.hash) {
							const extracted = extractedFilesMap.get(f.path);
							if (extracted) {
								if (extracted.hash !== f.hash) {
									this.result.warnings.push(`Hash mismatch for ${f.path}. Expected ${f.hash}, got ${extracted.hash}. Skipping this file.`);
									
									// Soft Fail: Delete the corrupted file from the temporary cache so the executor cannot install it.
									const corruptedPath = path.join(this.result.archiveRoot, f.path);
									if (fs.existsSync(corruptedPath)) {
										await fs.promises.unlink(corruptedPath);
									}
								}
							}
						}
					}
				}
			}

			this.state = 'completed';
			this.result.success = true;

		} catch (error) {
			this.state = 'failed';
			this.result.errors.push(error.message);
			await tempManager.cleanExtracted();
			this.plugin.notifyUI();
		}
	}
}

class GitHubService {
	constructor(plugin) { 
		this.plugin = plugin; 
		this.cache = null; 
		this.cacheTimestamp = 0;
		this.CACHE_DURATION_MS = 60 * 60 * 1000; // 1 hour cache expiration
		this.rateLimitReset = 0;
	}

	// A token means requests are billed against the user's personal 5,000/hr quota
	// instead of the 60/hr quota shared by every device on the network's public IP.
	isAuthenticated() {
		return typeof this.plugin.settings.githubToken === 'string' && this.plugin.settings.githubToken.trim().length > 0;
	}

	_authHeaders() {
		const headers = { 'Accept': 'application/vnd.github+json' };
		if (this.isAuthenticated()) {
			headers['Authorization'] = `Bearer ${this.plugin.settings.githubToken.trim()}`;
		}
		return headers;
	}

	// Cooldown between checks. Unauthenticated requests share a 60/hr network-wide budget,
	// so they get a long, conservative cooldown. Authenticated requests use a token-scoped
	// 5,000/hr budget and can safely check far more often.
	getCooldownMs() {
		return this.isAuthenticated() ? (15 * 60 * 1000) : (60 * 60 * 1000);
	}

	async refreshReleaseData(force = false) {
		const now = Date.now();
		
		// 2. Cache expiration
		if (!force && this.cache && (now - this.cacheTimestamp < this.CACHE_DURATION_MS)) {
			return this.cache;
		}

		const { repositoryOwner, repositoryName, releaseChannel } = this.plugin.settings;
		if (!repositoryOwner || !repositoryName) {
			this.plugin.vaultStatus.connectionStatus = "Configuration Error";
			return null;
		}

		// FIX: Completely bypass the GitHub API when in DEV_MODE with a target version.
		// This results in 0 API calls, guaranteeing you never hit GitHub's 60 req/hr rate limit.
		if (DEV_MODE && this.plugin.settings.devTargetVersion) {
			const devVersion = this.plugin.settings.devTargetVersion.trim();
			console.log(`[GATE Manager] DEV_MODE: Bypassing GitHub API to avoid rate limits for target: ${devVersion}`);
			
			this.plugin.vaultStatus.repoName = `${repositoryOwner}/${repositoryName}`;
			this.plugin.vaultStatus.latestVersion = devVersion;
			this.plugin.vaultStatus.latestReleaseDate = "Developer Override";
			this.plugin.vaultStatus.releaseNotes = "API bypassed in DEV_MODE to prevent rate limits. Check GitHub directly for release notes.";
			
			// Direct predictable URL structure for GitHub release tags
			this.plugin.vaultStatus.downloadUrl = `https://github.com/${repositoryOwner}/${repositoryName}/archive/refs/tags/${devVersion}.zip`;
			this.plugin.vaultStatus.connectionStatus = "Connected";
			
			const dummyRelease = { tag_name: devVersion, name: devVersion, prerelease: false };
			this.cache = dummyRelease;
			this.cacheTimestamp = Date.now();
			return dummyRelease;
		}

		// Prevent requests if we know we are still rate-limited (Ignored in DEV_MODE to allow manual retries)
		if (!DEV_MODE && now < this.rateLimitReset) {
			const resetTime = new Date(this.rateLimitReset).toLocaleTimeString();
			this.plugin.vaultStatus.connectionStatus = `Rate limited until ${resetTime}`;
			return null;
		}

		try {
			const authHeaders = this._authHeaders();
			const repoResponse = await fetch(`https://api.github.com/repos/${repositoryOwner}/${repositoryName}`, { headers: authHeaders });
			
			// 1. Proper GitHub rate-limit handling
			const remaining = repoResponse.headers.get('x-ratelimit-remaining');
			const reset = repoResponse.headers.get('x-ratelimit-reset');
			if (reset) this.rateLimitReset = parseInt(reset, 10) * 1000;

			if (repoResponse.status === 401) throw new Error("Invalid GitHub token. Check the token in Advanced Settings.");
			if (repoResponse.status === 403 && remaining === '0') {
				const resetTime = new Date(this.rateLimitReset).toLocaleTimeString();
				throw new Error(`Rate limited until ${resetTime}`);
			}
			if (repoResponse.status === 404) throw new Error("Repository not found");
			if (!repoResponse.ok) throw new Error(`GitHub API error: ${repoResponse.status}`);

			const repoData = await repoResponse.json();
			this.plugin.vaultStatus.repoName = repoData.full_name;

			const releasesResponse = await fetch(`https://api.github.com/repos/${repositoryOwner}/${repositoryName}/releases`, { headers: authHeaders });
			
			const relRemaining = releasesResponse.headers.get('x-ratelimit-remaining');
			const relReset = releasesResponse.headers.get('x-ratelimit-reset');
			if (relReset) this.rateLimitReset = parseInt(relReset, 10) * 1000;

			if (releasesResponse.status === 403 && relRemaining === '0') {
				const resetTime = new Date(this.rateLimitReset).toLocaleTimeString();
				throw new Error(`Rate limited until ${resetTime}`);
			}
			if (!releasesResponse.ok) throw new Error("Failed to fetch releases");
			
			const releases = await releasesResponse.json();
			if (!releases || releases.length === 0) throw new Error("No releases found");

			let targetRelease = null;

			// 3. Stable semantic-version release selection
			const getVersionName = (r) => r.tag_name || r.name || "0.0.0";
			
			if (releaseChannel === "stable") {
				const stableReleases = releases.filter(r => !r.prerelease);
				stableReleases.sort((a, b) => VersionUtils.compareVersions(getVersionName(b), getVersionName(a)));
				// Fallback to latest overall if no stable releases exist
				targetRelease = stableReleases.length > 0 ? stableReleases[0] : releases[0];
			} else {
				const allReleases = [...releases];
				allReleases.sort((a, b) => VersionUtils.compareVersions(getVersionName(b), getVersionName(a)));
				targetRelease = allReleases[0];
			}

			if (targetRelease) {
				this.plugin.vaultStatus.latestVersion = targetRelease.tag_name || targetRelease.name;
				this.plugin.vaultStatus.latestReleaseDate = new Date(targetRelease.published_at).toLocaleDateString();
				this.plugin.vaultStatus.releaseNotes = targetRelease.body || "No release notes provided.";
				
				const zipAsset = targetRelease.assets?.find(a => a.name.endsWith('.zip'));
				if (zipAsset) this.plugin.vaultStatus.downloadUrl = zipAsset.browser_download_url;
				else if (targetRelease.zipball_url) this.plugin.vaultStatus.downloadUrl = targetRelease.zipball_url;
				else this.plugin.vaultStatus.downloadUrl = null;
			}

			this.plugin.vaultStatus.connectionStatus = "Connected";
			this.plugin.vaultStatus.authenticated = this.isAuthenticated();
			this.cache = targetRelease;
			this.cacheTimestamp = Date.now();
			return targetRelease;
		} catch (error) {
			if (error.message === "Failed to fetch") this.plugin.vaultStatus.connectionStatus = "Offline";
			else if (error.message.includes("Rate limited")) this.plugin.vaultStatus.connectionStatus = error.message;
			else if (error.message.includes("Invalid GitHub token")) this.plugin.vaultStatus.connectionStatus = error.message;
			else this.plugin.vaultStatus.connectionStatus = "Repository Unavailable";
			return null;
		}
	}
}

class DownloadManager {
	constructor(plugin) { this.plugin = plugin; this.resetState(); }
	
	resetState() {
		this.state = 'idle';
		this.progress = { received: 0, total: 0, percent: 0, speed: 0 };
		this.abortController = null;
		this.destPath = null;
		this.error = null;
	}

	async download(url) {
		if (!url || typeof url !== 'string') {
			this.plugin.showNotice("No downloadable archive found.");
			throw new Error("Invalid download URL.");
		}

		// Fail closed immediately: only https:// URLs on trusted GitHub hosts are ever
		// attempted, before any cache directories are even created.
		try {
			assertSafeDownloadUrl(url);
		} catch (validationError) {
			this.plugin.showNotice(validationError.message);
			throw validationError;
		}

		this.resetState();
		this.state = 'downloading';
		this.abortController = new AbortController();
		
		const tempManager = this.plugin.tempManager;
		await tempManager.prepareCache();
		this.destPath = tempManager.getArchivePath();

		this.plugin.notifyUI();

		try {
			await new Promise((resolve, reject) => {
				const doRequest = (currentUrl, redirectCount = 0) => {
					// 4. Better redirect handling: Prevent infinite redirect loops
					if (redirectCount > 10) return reject(new Error('Too many redirects.'));
					
					try {
						// Re-validated on every hop, not just the initial URL — a redirect
						// response is server-controlled, so it must clear the same https-only,
						// trusted-host bar as the original request. This is what actually
						// stops a compromised or malicious server from redirecting the
						// download somewhere else entirely.
						assertSafeDownloadUrl(currentUrl);
					} catch (validationError) {
						return reject(validationError);
					}
					const client = https; // http:// is blocked by assertSafeDownloadUrl above
					let requestDestroyed = false;

					const req = client.get(currentUrl, { 
						headers: { 'User-Agent': 'GATE-Manager-Obsidian-Plugin' },
						timeout: 15000 // 6. Improve timeout detection using native socket timeouts
					}, (res) => {
						if (this.abortController.signal.aborted) {
							res.destroy();
							const err = new Error('AbortError');
							err.name = 'AbortError';
							return reject(err);
						}

						// 4. Better redirect handling: Resolve relative Location headers securely
						if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
							res.resume(); 
							const redirectUrl = new URL(res.headers.location, currentUrl).href;
							doRequest(redirectUrl, redirectCount + 1);
							return;
						}

						if (res.statusCode >= 400) {
							res.resume();
							return reject(new Error(`Server returned HTTP ${res.statusCode}`));
						}

						const totalStr = res.headers['content-length'];
						this.progress.total = totalStr ? parseInt(totalStr, 10) : 0;

						let lastTime = Date.now(), lastReceived = 0;
						const writeStream = fs.createWriteStream(this.destPath);

						// 5. Remove abort-listener leaks: Keep reference to handler for cleanup
						const abortHandler = () => {
							requestDestroyed = true;
							req.destroy();
							writeStream.destroy();
							const err = new Error('AbortError');
							err.name = 'AbortError';
							reject(err);
						};
						this.abortController.signal.addEventListener('abort', abortHandler);

						const cleanup = () => {
							this.abortController.signal.removeEventListener('abort', abortHandler);
						};

						res.on('data', (chunk) => {
							this.progress.received += chunk.length;
							if (this.progress.total > 0) this.progress.percent = Math.floor((this.progress.received / this.progress.total) * 100);
							else this.progress.percent = 0; 
							
							const now = Date.now();
							if (now - lastTime >= 500) { 
								this.progress.speed = ((this.progress.received - lastReceived) / ((now - lastTime) / 1000));
								lastTime = now;
								lastReceived = this.progress.received;
								this.plugin.notifyUI();
							}
						});

						res.pipe(writeStream);
						
						writeStream.on('finish', () => {
							cleanup();
							writeStream.close((err) => {
								if (err) return reject(err);

								// 7. Verify downloaded archive before reporting success & 8. Improve download integrity checks
								try {
									const stats = fs.statSync(this.destPath);
									if (this.progress.total > 0 && stats.size !== this.progress.total) {
										throw new Error(`Download integrity failed: Expected ${this.progress.total} bytes but received ${stats.size} bytes.`);
									}
									if (stats.size === 0) {
										throw new Error("Download integrity failed: File is completely empty.");
									}
									resolve();
								} catch (verificationError) {
									reject(verificationError);
								}
							});
						});

						writeStream.on('error', (err) => {
							cleanup();
							if (!requestDestroyed) {
								fs.unlink(this.destPath, () => {}); 
								reject(err);
							}
						});
					});
					
					// 6. Improve timeout detection handling
					req.on('timeout', () => {
						requestDestroyed = true;
						req.destroy();
						reject(new Error("Download timed out. No data received for 15 seconds. Please check your internet connection."));
					});

					req.on('error', (err) => {
						if (!requestDestroyed) reject(err);
					});
				};
				
				doRequest(url);
			});

			this.state = 'completed';
			this.plugin.notifyUI();
		} catch (error) {
			if (this.destPath && fs.existsSync(this.destPath)) {
				try { fs.unlinkSync(this.destPath); } catch (e) {}
			}

			if (error.name === 'AbortError') {
				this.state = 'cancelled';
			} else {
				this.state = 'failed';
				this.error = error.message;
			}
			this.plugin.notifyUI();
		}
	}

	cancel() { 
		if (this.abortController) this.abortController.abort(); 
	}
}

class ExecutionResult {
	constructor() {
		this.success = false;
		this.errors = [];
		this.installedFilesCount = 0;
	}
}

class InstallationExecutor {
	constructor(plugin) { 
		this.plugin = plugin; 
		this.resetState(); 
	}
	
	resetState() {
		this.state = 'idle';
		this.result = null;
		this.progress = { current: 0, total: 0 };
	}

	async execute(planningResult, selectedActionIds) {
		this.resetState();
		this.state = 'executing';
		this.plugin.statusBarItemEl.setText("🔄 GATE: Installing...");
		this.plugin.notifyUI();

		this.result = new ExecutionResult();

		// The install/update flow reads and rewrites plugin state (history, statistics,
		// installedFiles) at the end of this run. If state hasn't finished loading yet
		// (e.g. this ran before StateLoader.load() completed, or that load somehow left
		// stateLoader.model unset), bail out now rather than doing file I/O we then can't
		// safely record — StateModel itself is now defensive against bad *data*, but a
		// completely missing model is a different failure the loop below shouldn't assume away.
		if (!this.plugin.stateLoader || !this.plugin.stateLoader.model) {
			this.state = 'failed';
			this.result.success = false;
			this.result.errors.push("Installation aborted: plugin state has not finished loading yet. Please wait a moment and try again.");
			this.plugin.notifyUI();
			return;
		}

		const vaultRoot = this.plugin.app.vault.adapter.getBasePath();
		const archiveRoot = this.plugin.extractionManager.result.archiveRoot;
		
		const allActions = planningResult.installPlan.actions;
		this.progress.total = allActions.filter(a => selectedActionIds.has(a.id)).length;
		const installedFilesList = [];
		let installedCount = 0;

		const backupDir = path.join(this.plugin.tempManager.getCacheDir(), 'backups', Date.now().toString());
		await fs.promises.mkdir(backupDir, { recursive: true });
		const rollbackLog = [];

		try {
			for (const action of allActions) {
				const destPath = path.join(vaultRoot, action.path);
				const srcPath = path.join(archiveRoot, action.path);

				// Retain state for actions skipped by user selection
				if (!selectedActionIds.has(action.id)) {
					if (action.stateEntry) installedFilesList.push(action.stateEntry);
					continue;
				}

				const destDir = path.dirname(destPath);
				await fs.promises.mkdir(destDir, { recursive: true });

				// Rollback tracking helper
				const backupIfNeeded = async (target) => {
					const exists = fs.existsSync(target);
					let backupPath = null;
					if (exists) {
						const uid = Date.now().toString() + '-' + Math.floor(Math.random() * 1000000);
						backupPath = path.join(backupDir, uid);
						await fs.promises.copyFile(target, backupPath);
					}
					rollbackLog.push({ type: 'file', dest: target, existed: exists, backup: backupPath });
				};

				// Undo a single bad file write immediately (integrity/hash mismatch on one file
				// shouldn't leave a corrupted file sitting in the vault just because the overall
				// install loop didn't throw). Restores the pre-install backup if one exists,
				// otherwise deletes the file we just created. Also removes the matching entry
				// from rollbackLog so the catastrophic end-of-run rollback doesn't try to process
				// an already-reverted entry a second time.
				const revertFile = async (target) => {
					for (let i = rollbackLog.length - 1; i >= 0; i--) {
						const log = rollbackLog[i];
						if (log.type === 'file' && log.dest === target) {
							try {
								if (log.existed && log.backup) {
									await fs.promises.copyFile(log.backup, log.dest);
								} else if (!log.existed && fs.existsSync(log.dest)) {
									await fs.promises.unlink(log.dest);
								}
							} catch (revertErr) {
								console.error(`[GATE Manager] Failed to revert bad file ${target}:`, revertErr);
							}
							rollbackLog.splice(i, 1);
							return;
						}
					}
					// No matching backup entry found — still don't leave a corrupt file behind.
					if (fs.existsSync(target)) {
						try { await fs.promises.unlink(target); } catch (e) { console.error(`[GATE Manager] Failed to remove bad file ${target}:`, e); }
					}
				};

				// Process actions
				if (action.type === ActionType.SKIP || action.type === ActionType.IGNORE) {
					if (action.stateEntry) installedFilesList.push(action.stateEntry);
					this.progress.current++;
					continue;
				}

				if (action.type === ActionType.ARCHIVE) {
					if (fs.existsSync(destPath)) {
						const uniqueId = Date.now().toString() + '-' + Math.floor(Math.random() * 1000000);
						const archivePath = `${destPath}.${uniqueId}.archive`;
						await fs.promises.rename(destPath, archivePath);
						rollbackLog.push({ type: 'rename', from: archivePath, to: destPath });
					}
					this.progress.current++;
					continue;
				}

				if (action.type === ActionType.INSTALL || action.type === ActionType.UPDATE) {
					if (!fs.existsSync(srcPath)) {
						this.result.errors.push(`Skipped ${action.path}: File missing or failed integrity check during extraction.`);
						continue; // Soft Fail: Skip to the next file
					}
					
					await backupIfNeeded(destPath);
					await fs.promises.stat(srcPath);
					await fs.promises.copyFile(srcPath, destPath);
					
					const hash = await HashService.getFileHash(destPath);
					if (action.repositoryHash && hash !== action.repositoryHash) {
						this.result.errors.push(`Integrity verification failed for ${action.path} after copying. Skipping.`);
						await revertFile(destPath); // don't leave the corrupted copy in the vault
						continue; // Soft Fail: Skip to the next file
					}
					installedFilesList.push({ path: action.path, installedHash: hash, installDate: Date.now() });
					installedCount++;
					
				} else if (action.type === ActionType.CONFLICT) {
					if (!fs.existsSync(srcPath)) {
						this.result.errors.push(`Skipped conflict for ${action.path}: Incoming file missing.`);
						continue;
					}
					const conflictDest = destPath + '.repo';
					await backupIfNeeded(conflictDest);
					await fs.promises.stat(srcPath);
					await fs.promises.copyFile(srcPath, conflictDest);

					if (action.stateEntry) installedFilesList.push(action.stateEntry);
					installedCount++;
					
				} else if (action.type === ActionType.MERGE) {
					const strategy = action.mergeStrategy || 'Ours';
					if (strategy === 'Theirs') {
						if (!fs.existsSync(srcPath)) {
							this.result.errors.push(`Skipped merge for ${action.path}: Incoming file missing.`);
							continue;
						}
						await backupIfNeeded(destPath);
						await fs.promises.stat(srcPath);
						await fs.promises.copyFile(srcPath, destPath);

						const hash = await HashService.getFileHash(destPath);
						if (action.repositoryHash && hash !== action.repositoryHash) {
							this.result.errors.push(`Integrity verification failed for ${action.path} after merge. Skipping.`);
							await revertFile(destPath); // don't leave the corrupted copy in the vault
							continue;
						}
						installedFilesList.push({ path: action.path, installedHash: hash, installDate: Date.now() });
						installedCount++;
						
					} else if (strategy === 'Append') {
						if (!fs.existsSync(srcPath)) {
							this.result.errors.push(`Skipped append for ${action.path}: Incoming file missing.`);
							continue;
						}
						await backupIfNeeded(destPath);
						await fs.promises.stat(srcPath);
						const srcContent = await fs.promises.readFile(srcPath, 'utf8');
						const prefix = fs.existsSync(destPath) ? '\n' : '';
						await fs.promises.appendFile(destPath, prefix + srcContent);

						const hash = await HashService.getFileHash(destPath);
						installedFilesList.push({ path: action.path, installedHash: hash, installDate: Date.now() });
						installedCount++;
						
					} else {
						if (action.stateEntry) installedFilesList.push(action.stateEntry);
					}
				}
				
				this.progress.current++;
				if (this.progress.current % 5 === 0) {
					this.plugin.statusBarItemEl.setText(`🔄 GATE: Installing ${this.progress.current}/${this.progress.total}`);
					this.plugin.notifyUI();
				}
			}
			
			// Only update state atomically after all file operations have succeeded without throwing
			// Guard against the model going null mid-run too (e.g. a concurrent stateLoader.load()
			// call resets it) — not just the upfront check before the loop started.
			const currentState = this.plugin.stateLoader.model || {};
			const history = Object.assign({}, currentState.history || {});
			if (!history.firstInstall) history.firstInstall = Date.now();
			history.lastInstall = Date.now();
			history.lastUpdate = Date.now();

			const stats = Object.assign({}, currentState.statistics || {});
			stats.installedFiles = installedFilesList.length;

			const newState = {
				stateVersion: 1,
				pluginVersion: this.plugin.manifest.version,
				installedRepository: planningResult.repositoryModel.repositoryName,
				installedVersion: (this.plugin.vaultStatus.latestVersion && this.plugin.vaultStatus.latestVersion !== "Unknown") 
					? this.plugin.vaultStatus.latestVersion 
					: planningResult.repositoryModel.repositoryVersion,
				installationType: "Standard",
				installedFiles: installedFilesList,
				installationDate: currentState.installationDate || Date.now(),
				lastUpdate: Date.now(),
				history: history,
				statistics: stats
			};
			
			await this.plugin.saveState(newState);
			
			this.result.success = true;
			this.result.installedFilesCount = installedCount;
			this.state = 'completed';
			
			await this.plugin.tempManager.cleanAll();

		} catch (error) {
			// Trigger rollback on any file I/O or validation failure
			for (let i = rollbackLog.length - 1; i >= 0; i--) {
				const log = rollbackLog[i];
				try {
					if (log.type === 'rename') {
						await fs.promises.rename(log.from, log.to);
					} else if (log.type === 'file') {
						if (log.existed && log.backup) {
							await fs.promises.copyFile(log.backup, log.dest);
						} else if (!log.existed) {
							if (fs.existsSync(log.dest)) {
								await fs.promises.unlink(log.dest);
							}
						}
					}
				} catch (rollbackErr) {
					console.error("[GATE Manager] Rollback step failed:", rollbackErr);
				}
			}

			this.state = 'failed';
			this.result.success = false;
			this.result.errors.push(error.message || "Installation failed and was safely rolled back.");
		}
		
		this.plugin.notifyUI();
	}
}

class FileDiffModal extends Modal {
	constructor(app, action, archiveRoot) {
		super(app);
		this.action = action;
		this.archiveRoot = archiveRoot;
		this.vaultRoot = app.vault.adapter.getBasePath();
	}

	computeDiffLines(oldStr, newStr) {
		const oldLines = oldStr.split('\n');
		const newLines = newStr.split('\n');
		
		let start = 0;
		while (start < oldLines.length && start < newLines.length && oldLines[start] === newLines[start]) {
			start++;
		}
		
		let endOld = oldLines.length - 1;
		let endNew = newLines.length - 1;
		while (endOld >= start && endNew >= start && oldLines[endOld] === newLines[endNew]) {
			endOld--;
			endNew--;
		}
		
		const midOld = oldLines.slice(start, endOld + 1);
		const midNew = newLines.slice(start, endNew + 1);
		
		const diff = [];
		
		// Fix: Limit 2D matrix size constraints aggressively (1 Million max elements approx) to stop OOM crashes
		if (midOld.length * midNew.length > 1000000) { 
			for (let o of midOld) diff.push({ type: 'remove', value: o });
			for (let n of midNew) diff.push({ type: 'add', value: n });
		} else {
			const dp = Array(midOld.length + 1).fill(0).map(() => Array(midNew.length + 1).fill(0));
			for (let i = 1; i <= midOld.length; i++) {
				for (let j = 1; j <= midNew.length; j++) {
					if (midOld[i - 1] === midNew[j - 1]) {
						dp[i][j] = dp[i - 1][j - 1] + 1;
					} else {
						dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
					}
				}
			}
			
			let i = midOld.length, j = midNew.length;
			const tempDiff = [];
			while (i > 0 || j > 0) {
				if (i > 0 && j > 0 && midOld[i - 1] === midNew[j - 1]) {
					tempDiff.push({ type: 'equal', value: midOld[i - 1] });
					i--; j--;
				} else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
					tempDiff.push({ type: 'add', value: midNew[j - 1] });
					j--;
				} else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
					tempDiff.push({ type: 'remove', value: midOld[i - 1] });
					i--;
				}
			}
			tempDiff.reverse();
			diff.push(...tempDiff);
		}
		
		const result = [];
		for (let k = 0; k < start; k++) result.push({ type: 'equal', value: oldLines[k] });
		result.push(...diff);
		for (let k = endOld + 1; k < oldLines.length; k++) result.push({ type: 'equal', value: oldLines[k] });
		
		return result;
	}

	onOpen() {
		const { contentEl, titleEl } = this;
		
		titleEl.empty();
		const headerContainer = titleEl.createDiv({ attr: { style: 'display: flex; align-items: center; flex-wrap: wrap; gap: 4px;' } });
		
		headerContainer.createSpan({ 
			text: 'Comparing:', 
			cls: 'text-muted', 
			attr: { style: 'font-weight: normal; font-size: 0.85em; margin-right: 6px; text-transform: uppercase; letter-spacing: 0.05em;' } 
		});

		const parts = this.action.path.split('/');
		parts.forEach((part, index) => {
			const isLast = index === parts.length - 1;
			if (!isLast) {
				headerContainer.createSpan({ text: part, cls: 'text-muted', attr: { style: 'font-weight: 500;' } });
				headerContainer.createSpan({ text: '/', cls: 'text-muted', attr: { style: 'margin: 0 2px; opacity: 0.5;' } });
			} else {
				headerContainer.createSpan({ text: part, attr: { style: 'font-weight: 600; color: var(--text-normal);' } });
			}
		});

		contentEl.style.width = '80vw';
		contentEl.style.maxWidth = '900px';

		const isText = this.action.path.endsWith('.md') || this.action.path.endsWith('.txt');
		if (!isText) {
			contentEl.createEl('p', { text: 'Visual diff is only available for text files (.md, .txt).' });
			return;
		}

		let localContent = "";
		let incomingContent = "";

		try {
			const localPath = path.join(this.vaultRoot, this.action.path);
			if (fs.existsSync(localPath)) localContent = fs.readFileSync(localPath, 'utf8');
		} catch (e) { localContent = "Error reading local file."; }

		try {
			const incomingPath = path.join(this.archiveRoot, this.action.path);
			if (fs.existsSync(incomingPath)) incomingContent = fs.readFileSync(incomingPath, 'utf8');
		} catch (e) { incomingContent = "Error reading incoming file."; }

		const diffLines = this.computeDiffLines(localContent, incomingContent);

		const info = contentEl.createDiv({ attr: { style: 'display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 0.85em; color: var(--text-muted);' } });
		info.createSpan({ text: '− Removed (Your Local File)' });
		info.createSpan({ text: '+ Added (Incoming Repository)' });

		const diffViewer = contentEl.createDiv({ 
			attr: { 
				style: 'background: var(--background-primary); border: 1px solid var(--background-modifier-border); border-radius: 6px; padding: 10px; max-height: 60vh; overflow-y: auto; font-family: var(--font-monospace); font-size: 0.9em; line-height: 1.5; white-space: pre-wrap; word-break: break-word;' 
			} 
		});

		for (const line of diffLines) {
			const lineEl = diffViewer.createDiv({ attr: { style: 'padding: 0 4px; border-radius: 3px; display: flex; gap: 10px;' } });
			
			const marker = lineEl.createSpan({ attr: { style: 'width: 15px; flex-shrink: 0; user-select: none; opacity: 0.5; text-align: right;' } });
			const text = lineEl.createSpan({ text: line.value || ' ', attr: { style: 'flex: 1;' } });

			if (line.type === 'add') {
				lineEl.style.backgroundColor = 'rgba(var(--color-green-rgb, 46, 204, 113), 0.15)';
				lineEl.style.color = 'var(--text-normal)';
				text.style.color = 'var(--color-green, #2ecc71)';
				marker.textContent = '+';
			} else if (line.type === 'remove') {
				lineEl.style.backgroundColor = 'rgba(var(--color-red-rgb, 231, 76, 60), 0.15)';
				lineEl.style.color = 'var(--text-muted)';
				text.style.textDecoration = 'line-through';
				text.style.opacity = '0.8';
				marker.textContent = '−';
			} else {
				lineEl.style.color = 'var(--text-muted)';
				marker.textContent = ' ';
			}
		}
	}

	onClose() {
		this.contentEl.empty();
	}
}

class InstallPlanReviewModal extends Modal {
	constructor(app, plugin, planningResult, onConfirm) {
		super(app);
		this.plugin = plugin;
		this.planningResult = planningResult;
		this.onConfirm = onConfirm;
		this.selectedActionIds = new Set();
		this.checkboxMap = new Map();
		
		this.includedActions = [];
		this.excludedActions = [];

		for (const a of planningResult.installPlan.actions) {
			if (a.type !== ActionType.SKIP && a.type !== ActionType.IGNORE) {
				if (a.isMandatory || !this.isExcluded(a.path)) {
					this.includedActions.push(a);
					this.selectedActionIds.add(a.id);
				} else {
					this.excludedActions.push(a);
				}
			}
		}
	}

	// Fix: Filter logic adjusted to match nested items and subfolders properly
	isExcluded(p) {
		const filters = (this.plugin.settings.exclusionFilter || "").split(',').map(s => s.trim()).filter(s => s.length > 0);
		for (const f of filters) {
			if (p === f || p.startsWith(f + '/') || p.endsWith('/' + f) || p.includes('/' + f + '/')) {
				return true;
			}
		}
		return false;
	}

	buildTree(actions) {
		const root = { name: '/', children: {}, isFolder: true, actions: [] };
		for (const a of actions) {
			const parts = a.path.split('/');
			let curr = root;
			for (let i = 0; i < parts.length - 1; i++) {
				const folderName = parts[i];
				if (!curr.children[folderName]) {
					curr.children[folderName] = { name: folderName, children: {}, isFolder: true, path: parts.slice(0, i+1).join('/') };
				}
				curr = curr.children[folderName];
			}
			const filename = parts[parts.length - 1];
			curr.children[filename] = { name: filename, isFolder: false, action: a, path: a.path };
		}
		return root;
	}

	renderNode(container, node) {
		const row = container.createDiv({ attr: { style: 'display: flex; align-items: center; margin-left: 20px; padding: 4px 0;' } });
		
		if (node.isFolder) {
			const details = container.createEl('details', { attr: { open: true, style: 'margin-left: 20px; width: 100%;' } });
			const summary = details.createEl('summary', { attr: { style: 'cursor: pointer; font-weight: bold; padding: 4px 0; list-style-position: inside;' } });
			
			const folderCb = summary.createEl('input', { type: 'checkbox', cls: 'gate-folder-cb', attr: { style: 'margin-right: 8px;' } });
			summary.createEl('span', { text: `📁 ${node.name}` });
			
			const childActionIds = [];
			const gatherIds = (n) => {
				if (!n.isFolder) childActionIds.push(n.action.id);
				else Object.values(n.children).forEach(gatherIds);
			};
			gatherIds(node);

			folderCb.onchange = (e) => {
				const isChecked = e.target.checked;
				childActionIds.forEach(id => {
					const cb = this.checkboxMap.get(id);
					if (cb && cb.disabled) return; 

					if (isChecked) this.selectedActionIds.add(id);
					else this.selectedActionIds.delete(id);
					if (cb) cb.checked = isChecked;
				});
			};

			const childContainer = details.createDiv();
			let allChecked = true;
			for (const childName of Object.keys(node.children).sort()) {
				this.renderNode(childContainer, node.children[childName]);
			}

			childActionIds.forEach(id => {
				if (!this.selectedActionIds.has(id)) allChecked = false;
			});
			folderCb.checked = allChecked && childActionIds.length > 0;

		} else {
			const a = node.action;
			const cb = row.createEl('input', { type: 'checkbox', attr: { style: 'margin-right: 8px;' } });
			cb.checked = this.selectedActionIds.has(a.id);
			this.checkboxMap.set(a.id, cb);

			let typeColor = 'var(--text-normal)';
			if (a.type === ActionType.INSTALL) typeColor = 'var(--text-success)';
			else if (a.type === ActionType.UPDATE) typeColor = 'var(--text-accent)';
			else if (a.type === ActionType.CONFLICT) typeColor = 'var(--text-error)';
			else if (a.type === ActionType.ARCHIVE) typeColor = 'var(--text-warning)';

			const label = row.createEl('span', { attr: { style: `font-family: var(--font-monospace); cursor: pointer; color: ${typeColor};` } });
			
			if (a.isMandatory) {
				cb.checked = true;
				cb.disabled = true;
				label.innerHTML = `📄 ${node.name} 🔒 `;
				label.style.cursor = 'default';
			} else {
				label.innerHTML = `📄 ${node.name} `;
				cb.onchange = () => {
					if (cb.checked) this.selectedActionIds.add(a.id);
					else this.selectedActionIds.delete(a.id);
				};
				label.onclick = () => {
					cb.checked = !cb.checked;
					cb.onchange();
				};
			}

			label.createEl('small', { text: `[${a.type}]`, attr: { style: 'opacity: 0.6; margin-left: 5px;' } });

			if ([ActionType.UPDATE, ActionType.CONFLICT].includes(a.type)) {
				const viewBtn = row.createEl('button', { text: '👁️ View', attr: { style: 'margin-left: auto; padding: 2px 8px; font-size: 0.8em; background: transparent; box-shadow: none;' } });
				viewBtn.onclick = () => {
					new FileDiffModal(this.app, a, this.plugin.extractionManager.result.archiveRoot).open();
				};
			}
		}
	}

	renderSection(parentContainer, title, actions, isIncluded) {
		if (actions.length === 0) return;

		const sectionDiv = parentContainer.createDiv({ attr: { style: 'margin-bottom: 25px;' } });

		const headerFlex = sectionDiv.createDiv({ attr: { style: 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 5px;' } });
		
		const headerTitle = headerFlex.createEl('h3', { text: title, attr: { style: 'margin: 0; color: ' + (isIncluded ? 'var(--text-normal)' : 'var(--text-muted)') } });
		
		const controlsDiv = headerFlex.createDiv({ attr: { style: 'display: flex; gap: 20px; align-items: center;' } });

		const expandAllDiv = controlsDiv.createDiv({ attr: { style: 'display: flex; align-items: center; gap: 8px;' } });
		expandAllDiv.createEl('span', { text: 'Expand All', cls: 'text-muted', attr: { style: 'font-size: 0.9em; user-select: none;' } });
		new ToggleComponent(expandAllDiv)
			.setValue(true) 
			.onChange((value) => {
				const details = treeContainer.querySelectorAll('details');
				details.forEach(d => {
					if (value) d.setAttribute('open', '');
					else d.removeAttribute('open');
				});
			});

		const selectAllDiv = controlsDiv.createDiv({ attr: { style: 'display: flex; align-items: center; gap: 8px;' } });
		selectAllDiv.createEl('span', { text: 'Select All', cls: 'text-muted', attr: { style: 'font-size: 0.9em; user-select: none;' } });
		new ToggleComponent(selectAllDiv)
			.setValue(isIncluded) 
			.onChange((value) => {
				actions.forEach(a => {
					if (a.isMandatory) {
						this.selectedActionIds.add(a.id);
						return;
					}
					if (value) this.selectedActionIds.add(a.id);
					else this.selectedActionIds.delete(a.id);
					
					const cb = this.checkboxMap.get(a.id);
					if (cb && !cb.disabled) cb.checked = value;
				});
				
				const folderCbs = treeContainer.querySelectorAll('.gate-folder-cb');
				folderCbs.forEach(cb => cb.checked = value);
			});

		const treeContainer = sectionDiv.createDiv();
		const tree = this.buildTree(actions);
		for (const childName of Object.keys(tree.children).sort()) {
			this.renderNode(treeContainer, tree.children[childName]);
		}
	}

	onOpen() {
		const { contentEl, titleEl } = this;
		titleEl.setText('Review Vault Installation Plan');
		
		contentEl.createEl('p', { text: 'Review the folders and files. Use the toggles to easily include/exclude or expand/collapse sections.' });

		const container = contentEl.createDiv({ attr: { style: 'max-height: 60vh; overflow-y: auto; background: var(--background-secondary); padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid var(--background-modifier-border);' } });
		
		if (this.includedActions.length === 0 && this.excludedActions.length === 0) {
			container.createEl('p', { text: 'No actionable files found. All files are up to date or ignored.' });
		} else {
			this.renderSection(container, 'Included Actions', this.includedActions, true);
			this.renderSection(container, 'Excluded Actions (by filter)', this.excludedActions, false);
		}
		
		const btnContainer = contentEl.createDiv({ attr: { style: 'display: flex; justify-content: flex-end; gap: 10px;' } });
		
		const cancelBtn = btnContainer.createEl('button', { text: 'Cancel' });
		cancelBtn.onclick = () => this.close();
		
		const confirmBtn = btnContainer.createEl('button', { text: 'Confirm & Install', cls: 'mod-cta' });
		confirmBtn.onclick = () => {
			this.onConfirm(this.selectedActionIds);
			this.close();
		};
	}

	onClose() {
		this.contentEl.empty();
	}
}

class OnboardingModal extends Modal {
	constructor(app, plugin) {
		super(app);
		this.plugin = plugin;
	}
	
	onOpen() {
		const { contentEl, titleEl } = this;
		titleEl.setText('Welcome to GATE Manager');
		contentEl.style.textAlign = 'center';

		contentEl.createEl('h2', { text: 'Your Study Vault Awaits!' });
		contentEl.createEl('p', { text: 'GATE Manager keeps your study notes perfectly synced with the community repository without overwriting your personal modifications.' });
		
		contentEl.createEl('br');
		
		const settingsDiv = contentEl.createDiv({ attr: { style: 'text-align: left; background: var(--background-secondary); padding: 15px; border-radius: 8px;' } });
		settingsDiv.createEl('h4', { text: 'Default Repository Connection', attr: { style: 'margin-top: 0;' }});
		
		new Setting(settingsDiv)
			.setName('Repository Owner')
			.addText(text => text.setValue(this.plugin.settings.repositoryOwner).onChange(v => this.plugin.settings.repositoryOwner = v));
			
		new Setting(settingsDiv)
			.setName('Repository Name')
			.addText(text => text.setValue(this.plugin.settings.repositoryName).onChange(v => this.plugin.settings.repositoryName = v));
		
		contentEl.createEl('br');

		const btn = contentEl.createEl('button', { text: 'Start using GATE Manager', cls: 'mod-cta', attr: { style: 'width: 100%; padding: 10px; font-size: 1.1em;' } });
		btn.onclick = async () => {
			this.plugin.settings.hasCompletedOnboarding = true;
			await this.plugin.saveSettings();
			this.close();
			this.plugin.openManager();
		};
	}

	onClose() { this.contentEl.empty(); }
}

class ReleaseNotesModal extends Modal {
	constructor(app, plugin) {
		super(app);
		this.plugin = plugin;
	}

	async onOpen() {
		const { contentEl, titleEl } = this;
		titleEl.setText(`Release Notes: ${this.plugin.vaultStatus.latestVersion || "Unknown"}`);
		contentEl.style.width = '80vw';
		contentEl.style.maxWidth = '800px';

		const container = contentEl.createDiv({ 
			cls: 'markdown-rendered',
			attr: { style: 'margin-top: 15px; padding: 15px; background: var(--background-secondary); border-radius: 8px; border: 1px solid var(--background-modifier-border); max-height: 60vh; overflow-y: auto; user-select: text;' }
		});
		
		const markdown = this.plugin.vaultStatus.releaseNotes || "No release notes provided.";

		try {
			if (typeof MarkdownRenderer.render === 'function') {
				await MarkdownRenderer.render(this.app, markdown, container, "", this);
			} else {
				await MarkdownRenderer.renderMarkdown(markdown, container, "", this);
			}
		} catch (error) {
			console.error("[GATE Manager] Failed to render release notes:", error);
			container.empty();
			container.createEl('pre', { text: markdown, attr: { style: 'white-space: pre-wrap; word-wrap: break-word;' } });
		}
	}

	onClose() {
		this.contentEl.empty();
	}
}

// ==========================================
// Native UI View implementation for Dashboard
// ==========================================

class GateManagerView extends ItemView {
	constructor(leaf, plugin) {
		super(leaf);
		this.plugin = plugin;
		this.uiCallback = () => this.refreshUI();
	}

	getViewType() {
		return VIEW_TYPE_GATE_MANAGER;
	}

	getDisplayText() {
		return "GATE Dashboard";
	}

	getIcon() {
		return "library"; 
	}

	async onOpen() {
		this.plugin.registerUICallback(this.uiCallback);
		const container = this.contentEl;
		container.empty();
		
		this.mainContainer = container.createDiv({ 
			attr: { style: 'max-width: 800px; margin: 0 auto; padding: 2rem 1rem;' } 
		});

		const loadingEl = this.mainContainer.createEl('p', { text: 'Connecting to repository...' });
		await this.plugin.checkForUpdates(true, true);
		loadingEl.remove();

		this.renderContent(this.mainContainer);
	}

	async onClose() {
		this.plugin.unregisterUICallback(this.uiCallback);
	}

	refreshUI() {
		const dm = this.plugin.downloadManager;
		const em = this.plugin.extractionManager;
		const rml = this.plugin.repositoryModelLoader;
		const vsm = this.plugin.vaultScanner;
		const sl = this.plugin.stateLoader;
		const pl = this.plugin.installationPlanner;
		const exec = this.plugin.installationExecutor;
		
		const isProcessing = dm.state === 'downloading' || 
							 em.state === 'extracting' || 
							 em.state === 'verifying' || 
							 rml.state === 'loading' || 
							 rml.state === 'validating' || 
							 vsm.state === 'scanning' ||
							 sl.state === 'loading' ||
							 pl.state === 'planning' ||
							 exec.state === 'executing';
		
		if (isProcessing) {
			this.updateProgressUI();
		} else {
			this.renderActionsContainer();
		}
	}

	renderContent(contentEl) {
		contentEl.empty();

		const header = contentEl.createDiv({ attr: { style: 'text-align: center; margin-bottom: 2rem;' } });
		header.createEl('h2', { text: 'GATE Dashboard', attr: { style: 'margin-bottom: 0.5rem;' } });
		header.createEl('p', { text: 'Community-managed installer and updater for your GATE study vault.', cls: 'text-muted' });

		const statusCard = contentEl.createDiv({ attr: { style: 'border: 1px solid var(--background-modifier-border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; background: var(--background-secondary);' } });
		statusCard.createEl('h3', { text: 'Vault Overview', attr: { style: 'margin-top: 0; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 0.5rem;' } });
		
		const statusGrid = statusCard.createDiv({ attr: { style: 'display: grid; grid-template-columns: auto 1fr; gap: 10px 20px; align-items: center;' } });
		const addRow = (label, value) => {
			statusGrid.createDiv({ text: label, cls: 'text-muted', attr: { style: 'font-weight: 400;' } });
			statusGrid.createDiv({ text: value, attr: { style: 'color: var(--text-normal);' } });
		};

		const status = this.plugin.vaultStatus;
		addRow("Repository Connection", status.connectionStatus);
		addRow("Target Repository", status.repoName);
		addRow("Installed Version", status.installedVersion || "Not Installed");
		addRow("Latest Available", status.latestVersion);
		addRow("Published Date", status.latestReleaseDate);
		addRow("Release Channel", this.plugin.settings.releaseChannel.charAt(0).toUpperCase() + this.plugin.settings.releaseChannel.slice(1));

		const btnDiv = statusCard.createDiv({ attr: { style: 'margin-top: 1rem; display: flex; justify-content: flex-end;' } });
		const notesBtn = btnDiv.createEl('button', { text: 'View Release Notes' });
		notesBtn.disabled = (status.connectionStatus !== "Connected" || !status.latestVersion);
		notesBtn.onclick = () => new ReleaseNotesModal(this.app, this.plugin).open();

		this.actionsContainerEl = contentEl.createDiv({ attr: { style: 'margin-bottom: 1.5rem;' } });
		this.renderActionsContainer();

		const resourcesCard = contentEl.createDiv({ attr: { style: 'border: 1px solid var(--background-modifier-border); border-radius: 8px; padding: 1.5rem; background: var(--background-secondary);' } });
		resourcesCard.createEl('h3', { text: 'Community & Support', attr: { style: 'margin-top: 0; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 0.5rem;' } });
		
		const linkDiv = resourcesCard.createDiv({ attr: { style: 'display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px;' } });
		const addLinkBtn = (text, url, isPrimary=false) => {
			const btn = linkDiv.createEl('button', { text: text });
			if (isPrimary) btn.addClass('mod-cta');
			btn.onclick = () => this.plugin.openExternalLink(url);
		};

		addLinkBtn('GitHub Repo', `https://github.com/${this.plugin.settings.repositoryOwner}/${this.plugin.settings.repositoryName}`);
		addLinkBtn('Join YouTube Channel', 'https://www.youtube.com/@zettelforgate');
		addLinkBtn('Join Telegram Channel', 'https://t.me/gate_ee0');
		addLinkBtn('Email', 'mailto:zettelforgate@gmail.com');
		addLinkBtn('Support the Creator', 'https://razorpay.me/@anandbaghel', true);
	}

	renderActionsContainer() {
		this.actionsContainerEl.empty();
		
		const dm = this.plugin.downloadManager;
		const vm = this.plugin.verificationManager.result;
		const em = this.plugin.extractionManager;
		const rml = this.plugin.repositoryModelLoader;
		const vsm = this.plugin.vaultScanner;
		const sl = this.plugin.stateLoader;
		const pl = this.plugin.installationPlanner;
		const exec = this.plugin.installationExecutor;

		const isProcessing = dm.state === 'downloading' || 
							 em.state === 'extracting' || 
							 em.state === 'verifying' || 
							 rml.state === 'loading' || 
							 rml.state === 'validating' || 
							 vsm.state === 'scanning' ||
							 sl.state === 'loading' ||
							 pl.state === 'planning' ||
							 exec.state === 'executing';

		if (isProcessing) {
			this.renderProgressPanel();
		} else if (exec.state === 'completed') {
			this.renderExecutionCompletePanel(exec.result);
		} else if (exec.state === 'failed') {
			this.renderExecutionFailedPanel(exec.result);
		} else if (pl.state === 'completed') {
			if (pl.result && pl.result.isValid) {
				this.renderPlanningReadyPanel(pl.result);
			} else {
				this.renderPlanningFailedPanel(pl.result);
			}
		} else if (pl.state === 'failed') {
			this.renderPlanningFailedPanel(pl.result);
		} else if (sl.state === 'completed' && (!sl.model || !sl.model.isValid)) {
			this.renderStateInvalidPanel(sl.model);
		} else if (vsm.state === 'failed') {
			this.renderVaultFailedPanel(vsm.model);
		} else if (rml.state === 'completed' && (!rml.model || !rml.model.isValid)) {
			this.renderRepositoryInvalidPanel(rml.model);
		} else if (em.state === 'failed') {
			this.renderExtractionFailedPanel(em.result);
		} else if (dm.state === 'completed' && vm && vm.state === 'failed') {
			this.renderVerificationFailedPanel(vm);
		} else {
			let desc = 'Keep your study materials fresh by syncing with the community repository.';
			let btnText = 'Install / Update GATE Vault';

			if (sl.state === 'failed') {
				desc = 'Plugin state loader failed.';
				btnText = 'Retry Scan';
			} else if (vsm.state === 'failed') {
				desc = 'Vault scan failed.';
				btnText = 'Retry Scan';
			} else if (dm.state === 'failed') {
				desc = `Download failed: ${dm.error}`;
				btnText = 'Retry Download';
			} else if (dm.state === 'cancelled') {
				desc = 'Download was cancelled.';
			}

			const status = this.plugin.vaultStatus;
			
			const actionBlock = new Setting(this.actionsContainerEl)
				.setName('Update Manager')
				.setDesc(desc);

			actionBlock.addButton(btn => btn
				.setButtonText(btnText)
				.setCta()
				.setDisabled(status.connectionStatus !== "Connected" || !status.downloadUrl)
				.onClick(() => {
					this.plugin.startVaultDownload();
				})
			);

			if (dm.state === 'failed' || em.state === 'failed' || vsm.state === 'failed' || (vm && vm.state === 'failed')) {
				actionBlock.addButton(btn => btn
					.setButtonText('Clear Cache')
					.setWarning() 
					.onClick(async () => {
						await this.plugin.tempManager.cleanAll();
						this.plugin.resetAllManagers();
						this.renderActionsContainer();
						this.plugin.showNotice("Cache cleared.");
					})
				);
			} else {
				actionBlock.addButton(btn => btn
					.setButtonText('Refresh Check')
					.onClick(async () => {
						await this.plugin.checkForUpdates(false, true);
						this.renderActionsContainer();
					})
				);
			}
		}
	}

	renderProgressPanel() {
		const setting = new Setting(this.actionsContainerEl).setName('Processing...').setDesc(''); 
		const descEl = setting.descEl;
		descEl.style.display = 'flex';
		descEl.style.flexDirection = 'column';
		descEl.style.gap = '5px';
		descEl.style.marginTop = '5px';

		const progressEl = descEl.createEl('progress', { attr: { max: 100, value: 0 } });
		progressEl.style.width = '100%';
		
		const statsEl = descEl.createEl('span');
		statsEl.style.color = 'var(--text-muted)';

		const dm = this.plugin.downloadManager;
		if (dm.state === 'downloading') {
			setting.setName("Downloading Archive...");
			setting.addButton(btn => btn.setButtonText('Cancel').onClick(() => dm.cancel()));
		} else {
			setting.setName("Processing...");
		}

		this.progressUI = { setting, progressEl, statsEl };
		this.updateProgressUI();
	}

	updateProgressUI() {
		if (!this.progressUI) return;
		const dm = this.plugin.downloadManager;
		const em = this.plugin.extractionManager;
		const rml = this.plugin.repositoryModelLoader;
		const vsm = this.plugin.vaultScanner;
		const sl = this.plugin.stateLoader;
		const pl = this.plugin.installationPlanner;
		const exec = this.plugin.installationExecutor;

		if (dm.state === 'downloading') {
			this.progressUI.setting.setName("Downloading Archive...");
			const downloadedStr = FormatUtils.bytes(dm.progress.received);
			
			if (dm.progress.total > 0) {
				this.progressUI.progressEl.removeAttribute('aria-busy');
				this.progressUI.progressEl.value = dm.progress.percent;
				const totalStr = FormatUtils.bytes(dm.progress.total);
				this.progressUI.statsEl.textContent = `Downloaded: ${downloadedStr} / ${totalStr} (${dm.progress.percent}%)`;
			} else {
				this.progressUI.progressEl.removeAttribute('value'); // Makes progress bar an endless spinner
				this.progressUI.statsEl.textContent = `Downloading... ${downloadedStr} received`;
			}
		} else if (em.state === 'extracting') {
			this.progressUI.setting.setName("Extracting Archive...");
			if (em.progress.totalEntries > 0) {
				const percent = Math.floor((em.progress.extractedEntries / em.progress.totalEntries) * 100);
				this.progressUI.progressEl.value = percent;
				this.progressUI.statsEl.textContent = `Extracting files: ${em.progress.extractedEntries} / ${em.progress.totalEntries} (${percent}%)`;
			} else {
				this.progressUI.progressEl.removeAttribute('value');
				this.progressUI.statsEl.textContent = `Extracting files...`;
			}
		} else if (em.state === 'verifying') {
			this.progressUI.setting.setName("Verifying Extraction...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Validating internal vault structure...`;
		} else if (rml.state === 'loading') {
			this.progressUI.setting.setName("Loading Repository Model...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Reading repository metadata files...`;
		} else if (rml.state === 'validating') {
			this.progressUI.setting.setName("Validating Repository...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Cross-validating manifest, rules, and index...`;
		} else if (vsm.state === 'scanning') {
			this.progressUI.setting.setName("Scanning Vault...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Analyzing local vault filesystem...`;
		} else if (sl.state === 'loading') {
			this.progressUI.setting.setName("Loading Plugin State...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Reading local state database...`;
		} else if (pl.state === 'planning') {
			this.progressUI.setting.setName("Planning Installation...");
			this.progressUI.progressEl.removeAttribute('value');
			this.progressUI.statsEl.textContent = `Generating deterministic install plan...`;
		} else if (exec.state === 'executing') {
			this.progressUI.setting.setName("Installing Vault...");
			if (exec.progress.total > 0) {
				const percent = Math.floor((exec.progress.current / exec.progress.total) * 100);
				this.progressUI.progressEl.value = percent;
				this.progressUI.statsEl.textContent = `Applying actions: ${exec.progress.current} / ${exec.progress.total} (${percent}%)`;
			} else {
				this.progressUI.progressEl.removeAttribute('value');
				this.progressUI.statsEl.textContent = `Applying actions...`;
			}
		}
	}

	renderExecutionCompletePanel(result) {
		const setting = new Setting(this.actionsContainerEl).setName('Installation Complete');
		const summary = document.createDocumentFragment();
		
		if (result.success) {
			summary.append(createEl("span", { text: `Successfully installed/updated ${result.installedFilesCount} files.`, cls: 'gate-manager-success-text' }), createEl("br"));
			
			// If the installation succeeded but files were skipped (Soft Fail)
			if (result.errors && result.errors.length > 0) {
				summary.append(createEl("br"));
				summary.append(createEl("span", { text: `⚠️ Warning: ${result.errors.length} file(s) were skipped due to formatting/integrity mismatches. The rest of your vault was installed successfully.`, attr: { style: 'color: var(--text-warning); font-size: 0.9em;' } }), createEl("br"));
			}
		} else {
			summary.append(createEl("span", { text: `Completed with ${result.errors.length} critical errors.`, attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Dismiss').setCta().onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderExecutionFailedPanel(result) {
		const setting = new Setting(this.actionsContainerEl).setName('Installation Failed');
		const summary = document.createDocumentFragment();
		summary.append(createEl("strong", { text: "The installation process encountered errors:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		
		if (result && result.errors) {
			result.errors.slice(0, 10).forEach(err => summary.append("- ", err, createEl("br")));
			if (result.errors.length > 10) summary.append(`...and ${result.errors.length - 10} more errors.`, createEl("br"));
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderPlanningReadyPanel(result) {
		const wrapper = this.actionsContainerEl.createDiv({ 
			attr: { style: 'border: 1px solid var(--background-modifier-border); border-radius: 8px; padding: 1.5rem; background: var(--background-secondary); margin-bottom: 1.5rem;' } 
		});

		const totalSizeBytes = this.plugin.extractionManager.result.totalBytes || 0;
		const formattedSize = FormatUtils.bytes(totalSizeBytes);

		const headerFlex = wrapper.createDiv({ attr: { style: 'display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 10px; margin-bottom: 15px;' } });
		headerFlex.createEl('h3', { text: 'Installation Plan Ready', attr: { style: 'margin: 0;' } });
		headerFlex.createEl('span', { text: `${formattedSize} • Computed in ${result.planningDuration}ms`, cls: 'text-muted', attr: { style: 'font-size: 0.85em; font-variant-numeric: tabular-nums;' } });

		if (result.repositoryModel.dependencies && result.repositoryModel.dependencies.plugins && result.repositoryModel.dependencies.plugins.length > 0) {
			const depBox = wrapper.createDiv({ attr: { style: 'background: rgba(var(--color-accent-rgb), 0.1); border-left: 4px solid var(--color-accent); padding: 10px 15px; border-radius: 4px; margin-bottom: 15px;' } });
			depBox.createEl('span', { text: 'Requires Plugins: ', attr: { style: 'font-weight: 600;' } });
			depBox.createEl('span', { text: result.repositoryModel.dependencies.plugins.join(', '), attr: { style: 'color: var(--text-accent);' } });
		}

		if (result.warnings.length > 0) {
			const warnBox = wrapper.createDiv({ attr: { style: 'background: rgba(var(--color-yellow-rgb, 255, 153, 0), 0.1); border-left: 4px solid var(--color-yellow, #ff9900); padding: 10px 15px; border-radius: 4px; margin-bottom: 15px;' } });
			warnBox.createEl('span', { text: `Warnings (${result.warnings.length}): `, attr: { style: 'font-weight: 600; color: var(--text-warning);' } });
			warnBox.createEl('span', { text: 'Check the developer console (Ctrl+Shift+I) for detailed logs.', cls: 'text-muted' });
		}

		const grid = wrapper.createDiv({ attr: { style: 'display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 25px;' } });

		const addStatRow = (container, label, value, activeColor = null) => {
			const row = container.createDiv({ attr: { style: 'display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--background-modifier-border-hover); font-size: 0.9em;' } });
			row.createSpan({ text: label, cls: 'text-muted' });
			const valSpan = row.createSpan({ text: value.toString(), attr: { style: 'font-weight: 600; font-variant-numeric: tabular-nums;' } });
			if (value > 0 && activeColor) {
				valSpan.style.color = activeColor;
			}
		};

		const col1 = grid.createDiv();
		col1.createEl('h4', { text: 'Overview', attr: { style: 'margin-top: 0; margin-bottom: 10px; font-size: 1em; color: var(--text-normal);' } });
		addStatRow(col1, 'Repository Files', result.summary.RepositoryFiles);
		addStatRow(col1, 'Managed Files', result.summary.ManagedFiles);
		addStatRow(col1, 'Generated Actions', result.summary.TotalActions);

		const col2 = grid.createDiv();
		col2.createEl('h4', { text: 'Changes', attr: { style: 'margin-top: 0; margin-bottom: 10px; font-size: 1em; color: var(--text-normal);' } });
		addStatRow(col2, 'Install', result.summary.InstallCount, 'var(--text-success)');
		addStatRow(col2, 'Update', result.summary.UpdateCount, 'var(--text-accent)');
		addStatRow(col2, 'Archive', result.summary.ArchiveCount, 'var(--text-warning)');
		addStatRow(col2, 'Conflict', result.summary.ConflictCount, 'var(--text-error)');

		const col3 = grid.createDiv();
		col3.createEl('h4', { text: 'Unchanged', attr: { style: 'margin-top: 0; margin-bottom: 10px; font-size: 1em; color: var(--text-normal);' } });
		addStatRow(col3, 'Skip', result.summary.SkipCount);
		addStatRow(col3, 'Ignore', result.summary.IgnoreCount);
		addStatRow(col3, 'Merge', result.summary.MergeCount);

		const actionSetting = new Setting(this.actionsContainerEl)
			.setName('Ready to Install')
			.setDesc('Review the detailed plan and select specific files to include or exclude before overwriting.');
		
		actionSetting.addButton(btn => btn.setButtonText('Cancel').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
		
		actionSetting.addButton(btn => btn.setButtonText('Review & Install').setCta().onClick(() => {
			new InstallPlanReviewModal(this.app, this.plugin, result, async (selectedActionIds) => {
				await this.plugin.installationExecutor.execute(result, selectedActionIds);
				this.plugin.postInstallRoutine(result.repositoryModel); 
			}).open();
		}));
	}

	renderPlanningFailedPanel(result) {
		const setting = new Setting(this.actionsContainerEl).setName('Planning Failed');
		const summary = document.createDocumentFragment();
		summary.append(createEl("strong", { text: "The installation planner encountered an error:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		
		if (result && result.errors) {
			result.errors.forEach(err => summary.append("- ", err, createEl("br")));
		} else {
			summary.append("Unknown planning error.");
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderStateInvalidPanel(model) {
		const setting = new Setting(this.actionsContainerEl).setName('Plugin State Invalid');
		const summary = document.createDocumentFragment();
		summary.append(createEl("strong", { text: "The persistent plugin state failed validation:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		
		if (model && model.errors) {
			model.errors.forEach(err => summary.append("- ", err, createEl("br")));
		} else {
			summary.append("Unknown state validation error.");
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderRepositoryInvalidPanel(model) {
		const setting = new Setting(this.actionsContainerEl).setName('Repository Invalid');
		const summary = document.createDocumentFragment();
		summary.append(createEl("strong", { text: "The repository model failed validation:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		
		if (model && model.errors) {
			model.errors.forEach(err => summary.append("- ", err, createEl("br")));
			if (model.warnings.length > 0) {
				summary.append(createEl("br"), createEl("strong", { text: "Warnings:" }), createEl("br"));
				model.warnings.forEach(w => summary.append("- ", w, createEl("br")));
			}
		} else {
			summary.append("Unknown repository validation error.");
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderVaultFailedPanel(model) {
		const setting = new Setting(this.actionsContainerEl).setName('Vault Scan Failed');
		const summary = document.createDocumentFragment();
		summary.append(createEl("strong", { text: "The local vault filesystem failed validation:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		
		if (model && model.errors) {
			model.errors.forEach(err => summary.append("- ", err, createEl("br")));
		} else {
			summary.append("Unknown vault scanning error.");
		}
		
		setting.setDesc(summary);

		setting.addButton(btn => btn.setButtonText('Clear Cache').setWarning().onClick(async () => {
			await this.plugin.tempManager.cleanAll();
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
			this.plugin.showNotice("Cache cleared.");
		}));
		setting.addButton(btn => btn.setButtonText('Retry Download').setCta().onClick(() => {
			this.plugin.startVaultDownload();
		}));
		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderExtractionFailedPanel(emResult) {
		const setting = new Setting(this.actionsContainerEl).setName('Extraction Failed');
		const errList = document.createDocumentFragment();
		errList.append(createEl("strong", { text: "The archive failed to extract properly:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		emResult.errors.forEach(err => errList.append("- ", err, createEl("br")));
		setting.setDesc(errList);

		setting.addButton(btn => btn.setButtonText('Clear Cache').setWarning().onClick(async () => {
			await this.plugin.tempManager.cleanAll();
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
			this.plugin.showNotice("Cache cleared.");
		}));
		setting.addButton(btn => btn.setButtonText('Retry Download').setCta().onClick(() => {
			this.plugin.startVaultDownload();
		}));
		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}

	renderVerificationFailedPanel(vm) {
		const setting = new Setting(this.actionsContainerEl).setName('Verification Failed');
		const errList = document.createDocumentFragment();
		errList.append(createEl("strong", { text: "The downloaded archive failed integrity checks:", attr: { style: 'color: var(--text-error);' } }), createEl("br"));
		vm.errors.forEach(err => errList.append("- ", err, createEl("br")));
		setting.setDesc(errList);

		setting.addButton(btn => btn.setButtonText('Clear Cache').setWarning().onClick(async () => {
			await this.plugin.tempManager.cleanAll();
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
			this.plugin.showNotice("Cache cleared.");
		}));
		setting.addButton(btn => btn.setButtonText('Retry Download').setCta().onClick(() => {
			this.plugin.startVaultDownload();
		}));
		setting.addButton(btn => btn.setButtonText('Dismiss').onClick(() => {
			this.plugin.resetAllManagers();
			this.plugin.notifyUI();
		}));
	}
}

/**
 * GateManagerPlugin Implementation
 */
class GateManagerPlugin extends Plugin {
	
	async onload() {
		this.vaultStatus = new VaultStatus();
		this.gitHubService = new GitHubService(this);
		this.tempManager = new TempDirectoryManager(this);
		this.downloadManager = new DownloadManager(this);
		this.verificationManager = new ArchiveVerificationManager(this);
		this.extractionManager = new ArchiveExtractionManager(this);
		this.repositoryModelLoader = new RepositoryModelLoader(this);
		this.vaultScanner = new VaultScanner(this);
		this.stateLoader = new StateLoader(this);
		this.installationPlanner = new InstallationPlanner(this);
		this.installationExecutor = new InstallationExecutor(this);

		this.uiRefreshCallbacks = [];
		this.setupStatusBar();
		
		this._lastNoticeTime = 0;
		this._lastNoticeMsg = "";

		await this.loadSettings();
		await this.stateLoader.load();

		this.registerView(
			VIEW_TYPE_GATE_MANAGER,
			(leaf) => new GateManagerView(leaf, this)
		);
		
		if (!this.settings.hasCompletedOnboarding) {
			new OnboardingModal(this.app, this).open();
		}

		this.showNotice("GATE Manager loaded");
		
		// Event listener to toggle status bar visibility based on active view
		this.registerEvent(this.app.workspace.on('layout-change', () => this.updateStatusBarVisibility()));
		this.app.workspace.onLayoutReady(() => {
			this.updateStatusBarVisibility();
			this.updateStatusBar();
		});

		// Automatic background checks are only run when a GitHub token is configured.
		// Without a token, every user shares GitHub's 60 req/hr *per network IP* limit, so
		// silently auto-checking on every launch (across 10,000+ installs, many behind the
		// same office/school/VPN IP) can exhaust that budget for everyone on that network.
		// With a token, checks are billed against that user's own 5,000 req/hr quota instead.
		if (this.settings.autoCheckUpdates && this.gitHubService.isAuthenticated()) {
			this.checkForUpdates(true, false); // silent = true, isUserInitiated = false
		}

		this.addRibbonIcon('library', 'GATE Manager', () => this.openManager());
		this.registerCommands();
		this.addSettingTab(new GateManagerSettingTab(this.app, this));
	}

	onunload() { this.showNotice("GATE Manager unloaded"); }

	registerUICallback(cb) { this.uiRefreshCallbacks.push(cb); }
	unregisterUICallback(cb) { this.uiRefreshCallbacks = this.uiRefreshCallbacks.filter(func => func !== cb); }

	notifyUI() {
		this.updateStatusBar();
		for (const cb of this.uiRefreshCallbacks) cb();
	}

	setupStatusBar() {
		this.statusBarItemEl = this.addStatusBarItem();
		this.statusBarItemEl.style.cursor = 'pointer';
		this.statusBarItemEl.style.display = 'none'; // Hidden by default until layout is ready and checked
		
		// Allows clicking the status bar to cancel downloads or open the dashboard
		this.statusBarItemEl.addEventListener('click', () => {
			if (this.downloadManager.state === 'downloading') {
				if (confirm("Do you want to cancel the vault download?")) {
					this.downloadManager.cancel();
					this.showNotice("Download canceled.");
				}
			} else {
				this.openManager();
			}
		});
	}

	updateStatusBarVisibility() {
		if (!this.statusBarItemEl) return;
		const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE_GATE_MANAGER);
		if (leaves.length > 0) {
			this.statusBarItemEl.style.display = '';
		} else {
			this.statusBarItemEl.style.display = 'none';
		}
	}

	updateStatusBar() {
		if (!this.statusBarItemEl) return;
		const dm = this.downloadManager;
		const vm = this.verificationManager.result;
		const em = this.extractionManager;
		const rml = this.repositoryModelLoader;
		const vsm = this.vaultScanner;
		const sl = this.stateLoader;
		const pl = this.installationPlanner;
		const exec = this.installationExecutor;
		
		if (dm.state === 'downloading') {
			this.statusBarItemEl.setText(dm.progress.total > 0 ? `🔄 GATE: Downloading ${dm.progress.percent}%` : `🔄 GATE: Downloading...`);
		} else if (em.state === 'extracting') {
			this.statusBarItemEl.setText(`🔄 GATE: Extracting ${em.progress.extractedEntries}/${em.progress.totalEntries}`);
		} else if (em.state === 'verifying') {
			this.statusBarItemEl.setText(`⏳ GATE: Verifying Extraction...`);
		} else if (rml.state === 'loading') {
			this.statusBarItemEl.setText(`⏳ GATE: Loading Repository...`);
		} else if (rml.state === 'validating') {
			this.statusBarItemEl.setText(`⏳ GATE: Validating Repository...`);
		} else if (vsm.state === 'scanning') {
			this.statusBarItemEl.setText(`🔄 GATE: Scanning Vault...`);
		} else if (sl.state === 'loading') {
			this.statusBarItemEl.setText(`⏳ GATE: Loading Plugin State...`);
		} else if (pl.state === 'planning') {
			this.statusBarItemEl.setText(`⏳ GATE: Planning Installation...`);
		} else if (exec.state === 'executing') {
			this.statusBarItemEl.setText(`🔄 GATE: Installing...`);
		} else if (exec.state === 'completed') {
			this.statusBarItemEl.setText(`✅ GATE: Installation Complete`);
		} else if (exec.state === 'failed') {
			this.statusBarItemEl.setText(`❌ GATE: Installation Failed`);
		} else if (pl.state === 'completed' && pl.result && pl.result.isValid) {
			this.statusBarItemEl.setText(`✅ GATE: Plan Ready`);
		} else if (pl.state === 'failed' || (pl.result && !pl.result.isValid)) {
			this.statusBarItemEl.setText(`❌ GATE: Planning Failed`);
		} else if (sl.state === 'failed' || (sl.model && !sl.model.isValid)) {
			this.statusBarItemEl.setText(`❌ GATE: State Invalid`);
		} else if (vsm.state === 'failed') {
			this.statusBarItemEl.setText(`❌ GATE: Vault Scan Failed`);
		} else if (rml.state === 'completed' && !rml.model.isValid) {
			this.statusBarItemEl.setText(`❌ GATE: Repository Invalid`);
		} else if (em.state === 'failed') {
			this.statusBarItemEl.setText(`❌ GATE: Extraction Failed`);
		} else if (dm.state === 'completed' && (!vm || vm.state === 'pending')) {
			this.statusBarItemEl.setText(`✅ GATE: Download Complete`);
		} else if (vm && vm.state !== 'pending' && em.state === 'idle') {
			this.statusBarItemEl.setText(vm.state === 'verified' ? "✅ GATE: Archive Verified" : "❌ GATE: Verification Failed");
		} else {
			const text = this.vaultStatus.statusText;
			if (text === "Update Available") this.statusBarItemEl.setText(`🔄 GATE: ${text}`);
			else if (text === "Offline" || text.includes("Error")) this.statusBarItemEl.setText(`❌ GATE: ${text}`);
			else this.statusBarItemEl.setText(`✅ GATE: ${text}`);
		}
	}

	registerCommands() {
		this.addCommand({ id: 'open-gate-manager', name: 'Open GATE Manager', callback: () => this.openManager() });
		this.addCommand({ id: 'open-gate-manager-settings', name: 'Open GATE Manager Settings', callback: () => this.openGateManagerSettings() });
		this.addCommand({
			id: 'install-gate-vault',
			name: 'Install GATE Vault',
			callback: () => {
				this.openManager();
				const isProcessing = this.downloadManager.state === 'downloading' || 
									 this.extractionManager.state === 'extracting' || 
									 this.repositoryModelLoader.state === 'loading' || 
									 this.vaultScanner.state === 'scanning' ||
									 this.stateLoader.state === 'loading' ||
									 this.installationPlanner.state === 'planning' ||
									 this.installationExecutor.state === 'executing';
				if (!isProcessing) {
					this.startVaultDownload();
				}
			}
		});
		this.addCommand({ id: 'check-vault-updates', name: 'Check for Vault Updates', callback: () => this.checkForUpdates(false, true) });
	}

	resetAllManagers() {
		this.downloadManager.resetState();
		this.verificationManager.reset();
		this.extractionManager.resetState();
		this.repositoryModelLoader.resetState();
		this.vaultScanner.resetState();
		this.stateLoader.resetState();
		this.installationPlanner.resetState();
		this.installationExecutor.resetState();
	}

	async checkDiskSpace() {
		try {
			if (fs.promises && fs.promises.statfs) {
				const vaultRoot = this.app.vault.adapter.getBasePath();
				const stats = await fs.promises.statfs(vaultRoot);
				const freeBytes = stats.bavail * stats.bsize;
				// Require at least 1 GB (1024 * 1024 * 1024) of free space for safety
				const MIN_BYTES = 1073741824; 
				if (freeBytes < MIN_BYTES) {
					return { hasSpace: false, freeStr: FormatUtils.bytes(freeBytes) };
				}
			}
		} catch (e) {
			// Fail silently if statfs is not supported on the user's OS/Node version
		}
		return { hasSpace: true };
	}

	async startVaultDownload() {
		if (!this.vaultStatus.downloadUrl) {
			this.showNotice("No downloadable archive found.");
			return;
		}

		// DISK SPACE GUARD
		const spaceCheck = await this.checkDiskSpace();
		if (!spaceCheck.hasSpace) {
			this.showNotice(`Not enough disk space! Only ${spaceCheck.freeStr} available. Please free up at least 1 GB to update the GATE vault safely.`);
			return;
		}
		
		this.resetAllManagers();
		await this.downloadManager.download(this.vaultStatus.downloadUrl);
		
		if (this.downloadManager.state === 'completed') {
			await this.verificationManager.verify(this.downloadManager.destPath);
			
			if (this.verificationManager.result.state === 'verified') {
				await this.extractionManager.extract(this.downloadManager.destPath);

				if (this.extractionManager.state === 'completed') {
					await this.repositoryModelLoader.load(this.extractionManager.result.archiveRoot);
					
					if (this.repositoryModelLoader.state === 'completed' && this.repositoryModelLoader.model.isValid) {
						await this.vaultScanner.scan();
						
						if (this.vaultScanner.state === 'completed' && this.vaultScanner.model.isValid) {
							await this.stateLoader.load();
							
							if (this.stateLoader.state === 'completed' && this.stateLoader.model.isValid) {
								await this.installationPlanner.plan(
									this.repositoryModelLoader.model,
									this.vaultScanner.model,
									this.stateLoader.model
								);
							}
						}
					}
				}
			}
		}
	}

	async postInstallRoutine(repoModel) {
		if (this.installationExecutor.state !== 'completed' || !this.installationExecutor.result.success) return;
		
		if (this.settings.autoOpenChangelog && repoModel && repoModel.manifest && repoModel.manifest.changelog) {
			const changelogPath = repoModel.manifest.changelog;
			const file = this.app.vault.getAbstractFileByPath(changelogPath);
			if (file && file instanceof TFile) {
				await this.app.workspace.getLeaf('tab').openFile(file);
			}
		}
	}

	async checkForUpdates(silent = false, isUserInitiated = false) {
		const now = Date.now();

		// The cooldown now applies to every caller (manual clicks, startup auto-check, and
		// settings-triggered rechecks alike) — not just user-initiated ones. Previously only
		// user-initiated checks were throttled, which meant the automatic startup check and
		// the settings-save recheck could hit GitHub's API on every Obsidian launch / every
		// settings tweak with no persisted memory of the last call. On a shared network IP
		// (office, school, VPN) that unauthenticated 60/hr budget is shared by every GATE
		// Manager user on that network, so unthrottled auto-checks could exhaust it quickly.
		//
		// Authenticated (token present) checks use a shorter cooldown since they draw from
		// that user's own 5,000/hr quota instead of the shared unauthenticated one.
		if (!DEV_MODE) {
			const cooldownMs = this.gitHubService.getCooldownMs();
			const timeSinceLastCheck = now - (this.settings.lastUpdateCheckTime || 0);
			if (timeSinceLastCheck < cooldownMs) {
				const minutesLeft = Math.ceil((cooldownMs - timeSinceLastCheck) / 60000);
				if (!silent) this.showNotice(`Rate limit: Please wait ${minutesLeft} minute(s) before checking for updates again.`);
				return;
			}
		}

		if (!silent) this.showNotice("Checking for updates...");
		if (this.statusBarItemEl) this.statusBarItemEl.setText("⏳ GATE: Checking...");
		
		await this.gitHubService.refreshReleaseData(true);
		this.updateStatusBar();

		// Only start the cooldown when the check actually succeeded, or when GitHub itself
		// told us we're rate-limited. Previously this was recorded unconditionally right
		// after refreshReleaseData(), so a transient network blip, a misconfigured repo name,
		// or an invalid token would ALSO suppress the next check for a full cooldown window —
		// even though nothing meaningful was consumed from the rate-limit budget in those cases.
		// A user fixing a typo'd repo name or a bad token would then have to wait up to an hour
		// just to find out whether the fix worked.
		const succeeded = this.vaultStatus.connectionStatus === "Connected";
		const genuinelyRateLimited = typeof this.vaultStatus.connectionStatus === 'string' && this.vaultStatus.connectionStatus.startsWith('Rate limited');
		if (!DEV_MODE && (succeeded || genuinelyRateLimited)) {
			this.settings.lastUpdateCheckTime = now;
			await this._persistSettings();
		}

		if (!succeeded) {
			if (!silent) this.showNotice(`Update check failed: ${this.vaultStatus.connectionStatus}`);
			return;
		}
		
		const isUpdateAvailable = VersionUtils.compareVersions(this.vaultStatus.latestVersion, this.vaultStatus.installedVersion) > 0;
		if (isUpdateAvailable) {
			this.showNotice(`New GATE Vault version ${this.vaultStatus.latestVersion} available!`);
		} else if (!silent) {
			this.showNotice("Already up to date.");
		}
	}

	async openManager() {
		const { workspace } = this.app;
		let leaf = null;
		const leaves = workspace.getLeavesOfType(VIEW_TYPE_GATE_MANAGER);

		if (leaves.length > 0) {
			leaf = leaves[0];
		} else {
			leaf = workspace.getLeaf(true);
			await leaf.setViewState({ type: VIEW_TYPE_GATE_MANAGER, active: true });
		}
		workspace.revealLeaf(leaf);
	}

	openExternalLink(url) { window.open(url, '_blank'); }
	
	openGateManagerSettings() {
		const settingInterface = this.app.setting;
		if (settingInterface) {
			settingInterface.open();
			settingInterface.openTabById(this.manifest.id);
		} else {
			this.showNotice("Unable to open settings. Please open them manually.");
		}
	}

	showNotice(message) {
		if (this.settings && this.settings.enableNotifications) {
			if (this._lastNoticeMsg === message && (Date.now() - this._lastNoticeTime) < 3000) {
				return; 
			}
			new Notice(message);
			this._lastNoticeMsg = message;
			this._lastNoticeTime = Date.now();
		}
	}

	async loadSettings() {
		try {
			// Fix: Isolate settings data to a specific key space to avoid collisions with state
			const loadedData = await this.loadData() || {};
			const settingsData = loadedData.settings ? loadedData.settings : loadedData;
			this.settings = Object.assign({}, DEFAULT_SETTINGS, settingsData);

			// If the token was stored encrypted, decrypt it into memory for runtime use.
			// safeStorage keys are tied to the OS user profile and are NOT portable across
			// machines or accounts, so a failed decrypt here most likely means the vault
			// (and its data.json) was copied/synced to a different computer or user — in that
			// case we clear the unusable token and ask the user to re-enter it, rather than
			// silently sending a garbage Authorization header to GitHub.
			if (this.settings.githubTokenEncrypted) {
				const decrypted = TokenCrypto.decrypt(this.settings.githubTokenEncrypted);
				if (decrypted) {
					this.settings.githubToken = decrypted;
				} else {
					this.settings.githubToken = '';
					this.settings.githubTokenEncrypted = '';
					if (this.settings.autoCheckUpdates) {
						this.settings.autoCheckUpdates = false; // no longer eligible without a working token
					}
					new Notice("GATE Manager: Your saved GitHub token couldn't be decrypted (often happens after moving to a different computer/account). Please re-enter it in Advanced Settings.");
				}
			}
		} catch (error) {
			this.settings = Object.assign({}, DEFAULT_SETTINGS);
			new Notice("GATE Manager: Failed to load settings. Using defaults.");
		}
		// Snapshot of the fields that actually affect WHICH data GitHub returns. Only a change
		// to one of these should ever justify nulling the cache and re-checking for updates.
		this._lastRepoConfigSnapshot = this._repoConfigSnapshot();
	}

	_repoConfigSnapshot() {
		return {
			repositoryOwner: this.settings.repositoryOwner,
			repositoryName: this.settings.repositoryName,
			releaseChannel: this.settings.releaseChannel,
			githubToken: this.settings.githubToken
		};
	}

	// Builds the object actually written to data.json: encrypts the token via TokenCrypto
	// (OS-level secret storage) when available, so the plain-text token never touches disk;
	// falls back to writing it in plain text — same as the rest of data.json — when
	// encryption isn't available on this platform. `this.settings.githubToken` itself is
	// left untouched (still plain text in memory) for use by GitHubService at runtime.
	_settingsForDisk() {
		const toSave = Object.assign({}, this.settings);
		if (toSave.githubToken) {
			const encrypted = TokenCrypto.encrypt(toSave.githubToken);
			if (encrypted) {
				toSave.githubTokenEncrypted = encrypted;
				toSave.githubToken = ''; // don't duplicate the secret in plain text when we can encrypt it
			} else {
				toSave.githubTokenEncrypted = ''; // encryption unavailable — plain text is the only option here
			}
		} else {
			toSave.githubTokenEncrypted = '';
		}
		return toSave;
	}

	// Internal, silent persistence — no "Settings saved" notice, no recheck side-effects.
	// Used for bookkeeping fields (like lastUpdateCheckTime) that don't reflect a user
	// editing the settings tab and shouldn't trigger the settings-tab behavior below.
	async _persistSettings() {
		try {
			const existingData = await this.loadData() || {};
			existingData.settings = this._settingsForDisk();
			await this.saveData(existingData);
		} catch (error) {
			console.error("[GATE Manager] Failed to persist settings", error);
		}
	}

	// Called from the settings tab whenever the user changes something. Only clears the
	// GitHub cache and triggers a recheck if a field that actually changes the API request
	// (owner/name/channel/token) was modified — previously this fired unconditionally on
	// *every* settings change (including unrelated toggles like "Enable Notifications"),
	// which meant idly clicking through settings could burn through the rate-limit budget.
	async saveSettings() {
		try {
			const newSnapshot = this._repoConfigSnapshot();
			const previousSnapshot = this._lastRepoConfigSnapshot || {};
			const repoConfigChanged = Object.keys(newSnapshot).some(
				key => newSnapshot[key] !== previousSnapshot[key]
			);

			const existingData = await this.loadData() || {};
			existingData.settings = this._settingsForDisk();
			await this.saveData(existingData);
			this.showNotice("Settings saved");

			if (repoConfigChanged) {
				this.gitHubService.cache = null;
				this.checkForUpdates(true, false); // still subject to the cooldown gate above
			}

			this._lastRepoConfigSnapshot = newSnapshot;
		} catch (error) {
			new Notice("GATE Manager: Failed to save settings.");
		}
	}

	async saveState(stateData) {
		try {
			// Fix: Properly map to independent state node
			const existingData = await this.loadData() || {};
			existingData.state = stateData;
			await this.saveData(existingData);
			await this.stateLoader.load();
		} catch (error) {
			console.error("[GATE Manager] Failed to save state", error);
		}
	}
}

class GateManagerSettingTab extends PluginSettingTab {
	constructor(app, plugin) { 
		super(app, plugin); 
		this.plugin = plugin; 
	}
	
	display() {
		const { containerEl } = this;
		containerEl.empty();

		// SECTION: Updates & Version

		new Setting(containerEl)
			.setName('Support the Creator')
			.setDesc('If you find this plugin helpful for your studies, consider supporting its development.')
			.addButton(btn => btn
				.setButtonText('Support via Payment')
				.setCta()
				.onClick(() => {
					window.open('https://razorpay.me/@anandbaghel', '_blank'); 
				})
			);

		new Setting(containerEl)
			.setName('GATE Manager Version')
			.setDesc(`Current plugin version: ${this.plugin.manifest.version}`)
			.addButton(btn => btn
				.setButtonText('Check for Updates')
				.onClick(async () => {
					await this.plugin.checkForUpdates(false, true);
				})
			);

		new Setting(containerEl)
			.setName('Auto Check for Vault Updates')
			.setDesc(
				this.plugin.gitHubService.isAuthenticated()
					? 'Automatically check the GitHub repository for updates when Obsidian starts.'
					: 'Automatically check the GitHub repository for updates when Obsidian starts. Requires a GitHub Access Token (see Advanced Settings below) — without one, please use the "Check for Updates" button above instead.'
			)
			.addToggle(toggle => toggle
				.setValue(this.plugin.settings.autoCheckUpdates)
				.onChange(async (value) => {
					if (value && !this.plugin.gitHubService.isAuthenticated()) {
						toggle.setValue(false);
						this.plugin.showNotice('Add a GitHub Access Token in Advanced Settings first to enable automatic checks.');
						return;
					}
					this.plugin.settings.autoCheckUpdates = value;
					await this.plugin.saveSettings();
				})
			);

		// SECTION: Repository Connection
		new Setting(containerEl).setHeading().setName('Repository Connection');

		new Setting(containerEl)
			.setName('Repository Owner')
			.setDesc('The GitHub username or organization that owns the vault repository.')
			.addText(text => {
				text
					.setPlaceholder('e.g., username')
					.setValue(this.plugin.settings.repositoryOwner)
					.onChange((value) => {
						this.plugin.settings.repositoryOwner = value.trim();
					});

				text.inputEl.addEventListener('blur', async () => {
					this.plugin.settings.repositoryOwner = text.inputEl.value.trim();
					await this.plugin.saveSettings();
				});

				return text;
			});

		new Setting(containerEl)
			.setName('Repository Name')
			.setDesc('The name of the GitHub repository containing the vault releases.')
			.addText(text => {
				text
					.setPlaceholder('e.g., gate-vault')
					.setValue(this.plugin.settings.repositoryName)
					.onChange((value) => {
						this.plugin.settings.repositoryName = value.trim();
					});

				text.inputEl.addEventListener('blur', async () => {
					this.plugin.settings.repositoryName = text.inputEl.value.trim();
					await this.plugin.saveSettings();
				});

				return text;
			});

		new Setting(containerEl)
			.setName('Release Channel')
			.setDesc('Choose whether to receive stable releases or early beta versions of the notes.')
			.addDropdown(dropdown => dropdown
				.addOption('stable', 'Stable')
				.addOption('beta', 'Beta')
				.setValue(this.plugin.settings.releaseChannel)
				.onChange(async (value) => {
					this.plugin.settings.releaseChannel = value;
					await this.plugin.saveSettings();
				})
			);
		
		new Setting(containerEl)
			.setName('Verify Archive Integrity')
			.setDesc('Check the integrity of the downloaded archive against the repository\'s published checksums.')
			.addButton(btn => btn
				.setButtonText('Verify Now')
				.onClick(() => {
					window.open('https://github.com/' + this.plugin.settings.repositoryOwner + '/' + this.plugin.settings.repositoryName, '_blank'); 
				})
			);

		// SECTION: Filters & Exclusions
		new Setting(containerEl).setHeading().setName('Filters & Exclusions');

		new Setting(containerEl)
			.setName('Exclusion Filter')
			.setDesc('Comma-separated list of paths/folders to uncheck by default during installation.')
			.addTextArea(text => {
				text
					.setPlaceholder('e.g., .obsidian, 11. ERROR Logbook, SPEC.md, etc.')
					.setValue(this.plugin.settings.exclusionFilter)
					.onChange(async (value) => {
						this.plugin.settings.exclusionFilter = value;
						await this.plugin.saveSettings();
					});
				text.inputEl.rows = 3;
				text.inputEl.cols = 30;
				return text;
			})
			.addButton(btn => btn
				.setButtonText('Reset')
				.setTooltip('Reset to Default Exclusions')
				.onClick(async () => {
					this.plugin.settings.exclusionFilter = ".obsidian, scripts, tools, .gitattributes, CODE_OF_CONDUCT.md, CONTRIBUTING.md, INDEX_GENERATOR_SPEC.md, INDEX_SPEC.md, INSTALL_PLAN_SPEC.md, LICENSE, README.md, SPEC.md, UPDATE_POLICY.md, VAULT_RULES_SPEC.md, VAULT_SPEC.md, vault-index.json, vault-manifest.json, vault-rules.json";
					await this.plugin.saveSettings();
					this.display(); 
				})
			);

		// SECTION: Preferences
		new Setting(containerEl).setHeading().setName('Preferences');

		new Setting(containerEl)
			.setName('Auto-open Changelog')
			.setDesc('Automatically open the changelog file in a new tab after a successful installation.')
			.addToggle(toggle => toggle
				.setValue(this.plugin.settings.autoOpenChangelog)
				.onChange(async (value) => {
					this.plugin.settings.autoOpenChangelog = value;
					await this.plugin.saveSettings();
				})
			);

		new Setting(containerEl)
			.setName('Open Vault After Installation')
			.setDesc('Automatically open the GATE vault in a new Obsidian window after a successful installation.')
			.addToggle(toggle => toggle
				.setValue(this.plugin.settings.openVaultAfterInstall)
				.onChange(async (value) => {
					this.plugin.settings.openVaultAfterInstall = value;
					await this.plugin.saveSettings();
				})
			);

		new Setting(containerEl)
			.setName('Enable Notifications')
			.setDesc('Show startup, shutdown, and background process notifications.')
			.addToggle(toggle => toggle
				.setValue(this.plugin.settings.enableNotifications)
				.onChange(async (value) => {
					this.plugin.settings.enableNotifications = value;
					await this.plugin.saveSettings();
				})
			);

		// SECTION: Dashboard
		new Setting(containerEl).setHeading().setName('Dashboard');

		new Setting(containerEl)
			.setName('Open Dashboard')
			.setDesc('Open the main GATE Manager interface to install or update vaults.')
			.addButton(btn => btn
				.setButtonText('Open Manager')
				.setCta()
				.onClick(() => {
					this.plugin.app.setting.close(); 
					this.plugin.openManager();
				})
			);

        // --- Official Channels / Social Media ---
        containerEl.createEl('h3', { text: 'Official Channels' });

        const socialSetting = new Setting(containerEl)
            .setName('Connect with us')
            .setDesc('Reach out via official channels for support, updates, and announcements.');


		socialSetting.addButton(btn => {
            btn.setButtonText('Join Youtube Channel')
                .setTooltip('Join our official Youtube channel for updates and support.')
                .onClick(() => {
                    window.open('https://www.youtube.com/@zettelforgate', '_blank');
                });
        });

        socialSetting.addButton(btn => {
            btn.setButtonText('Join Telegram Channel')
                .setTooltip('Join our official Telegram channel for updates and support.')
                .onClick(() => {
                    window.open('https://t.me/gate_ee0', '_blank');
                });
        });

        socialSetting.addButton(btn => {
            btn.setButtonText('Email')
                .setTooltip('Send us an email')
                .onClick(() => {
                    window.open('mailto:zettelforgate@gmail.com', '_blank');
                });
        });

		// SECTION: Advanced Settings
		new Setting(containerEl).setHeading().setName('Advanced Settings');

		const storageNote = TokenCrypto.isAvailable()
			? "🔒 Stored encrypted at rest using your operating system's secure storage (Keychain/DPAPI/libsecret) — the token itself is never written to disk in plain text."
			: "⚠️ Stored in plain text in this vault's plugin data file (.obsidian/plugins/gate-manager/data.json). Your OS's secure storage isn't available on this platform/build, so this is the same as how Obsidian stores the rest of this plugin's settings — anyone with file access to your vault (or a backup/sync of it) could read this token from that file. Only paste in a token with the minimal 'public_repo' (read-only) scope, never one with broader permissions.";

		const tokenStatusDesc = this.plugin.gitHubService.isAuthenticated()
			? `✅ Token is set. Update checks now use your own higher limit and won't compete with other users on your network. ${storageNote}`
			: `Optional, but recommended. Without a token, update checks use a small limit that is shared by everyone on your WiFi/network (e.g. school, office). With a token, checks use your own personal, much larger limit instead — and automatic checks on startup are enabled. ${storageNote}`;

		new Setting(containerEl)
			.setName('GitHub Access Token (optional)')
			.setDesc(tokenStatusDesc)
			.addText(text => {
				text.inputEl.type = 'password';
				text.inputEl.autocomplete = 'off';
				text.inputEl.spellcheck = false;
				text
					.setPlaceholder('Paste your token here')
					.setValue(this.plugin.settings.githubToken)
					.onChange((value) => {
						this.plugin.settings.githubToken = value.trim();
					});

				text.inputEl.addEventListener('blur', async () => {
					this.plugin.settings.githubToken = text.inputEl.value.trim();
					await this.plugin.saveSettings();
					this.display(); // refresh so the description/status and auto-check toggle reflect the new state
				});

				return text;
			})
			.addExtraButton(btn => btn
				.setIcon('eye')
				.setTooltip('Show/hide token')
				.onClick(() => {
					// Only toggle the token field itself (first password-type input in this section)
					const tokenInput = containerEl.querySelector('input[placeholder="Paste your token here"]');
					if (tokenInput) {
						tokenInput.type = tokenInput.type === 'password' ? 'text' : 'password';
					}
				})
			);

		const tokenHelp = containerEl.createEl('div', { cls: 'setting-item-description' });
		tokenHelp.style.marginTop = '-8px';
		tokenHelp.style.marginBottom = '12px';
		tokenHelp.style.opacity = '0.8';
		tokenHelp.innerHTML = `Don't have a token? It's free and takes about a minute:<br>
			1. Go to <a href="https://github.com/settings/tokens/new?description=GATE%20Manager&scopes=public_repo" target="_blank">github.com/settings/tokens/new</a> (sign in to GitHub first)<br>
			2. Leave the default options, scroll down, and click "Generate token"<br>
			3. Copy the code shown (starts with "ghp_" or "github_pat_") and paste it above<br>
			<em>This token only allows reading public repositories — it cannot access or change anything else in your GitHub account. See the storage note above for exactly how it's kept on this device.</em>`;

		if (this.plugin.settings.githubToken) {
			new Setting(containerEl)
				.setName('Remove token')
				.setDesc('Stop using a personal access token and fall back to the shared, unauthenticated limit.')
				.addButton(btn => btn
					.setButtonText('Remove')
					.setWarning()
					.onClick(async () => {
						this.plugin.settings.githubToken = '';
						if (this.plugin.settings.autoCheckUpdates) {
							this.plugin.settings.autoCheckUpdates = false; // no longer eligible without a token
							this.plugin.showNotice('Automatic update checks disabled (require a token).');
						}
						await this.plugin.saveSettings();
						this.display();
					})
				);
		}

		// SECTION: Cache Management
		new Setting(containerEl).setHeading().setName('Cache Management');

        new Setting(containerEl)
            .setName('Clear cache')
            .setDesc('Remove all cached downloads and extracted files')
            .addButton(button => button
                .setButtonText('Clear Cache')
                .setWarning()
                .onClick(async () => {
                    await this.plugin.tempManager.cleanAll();
                    new Notice("Cache cleared.");
                }));

		// ==========================================
		// DEVELOPER MODE OPTIONS (Hidden by default)
		// ==========================================
		if (DEV_MODE) {
			new Setting(containerEl).setHeading().setName('Developer Options (DEV_MODE)');
			
			new Setting(containerEl)
				.setName('Force Target Version')
				.setDesc('Force the plugin to download a specific release tag (e.g., v0.0.5) instead of the latest. Leave blank to use latest.')
				.addText(text => {
					text
						.setPlaceholder('e.g., v0.0.5')
						.setValue(this.plugin.settings.devTargetVersion)
						.onChange((value) => {
							this.plugin.settings.devTargetVersion = value.trim();
						});

					text.inputEl.addEventListener('blur', async () => {
						this.plugin.settings.devTargetVersion = text.inputEl.value.trim();
						await this.plugin.saveSettings();
						new Notice("Target version forced. Check for updates to apply.");
					});

					return text;
				});
		}
	}
}

module.exports = GateManagerPlugin;
