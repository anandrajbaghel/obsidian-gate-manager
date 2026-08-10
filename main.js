const { Plugin, PluginSettingTab, Setting, Notice, Modal, ItemView, requestUrl, ToggleComponent, SecretComponent } = require('obsidian');

const VIEW_TYPE_GATE_MANAGER = "gate-manager-view";

const DEFAULT_SETTINGS = {
	repositoryOwner: "anandrajbaghel",
	repositoryName: "gate-vault",
	installList: "1. Mathematics, 2. Electric Circuits, 3. Electromagnetic Fields, 4. Signal & Systems, 5. Electrical Machines, 6. Power Systems, 7. Control Systems, 8. Electrical & Electronic Measurements, 9. Analog & Digital Electronics, 10. Power Electronics, 11. ERROR Logbook, 12. PYQs Pattern Book, 13. REVISION Sheets 📙, 14. Reading List 📃, 15. Master, Resources",
	preserveList: ".obsidian, .trash",
	installedVersion: "None",
	// This stores the *name* of a secret in Obsidian's SecretStorage, never
	// the token itself. The actual PAT lives in SecretStorage, keyed to the
	// vault, so it never touches this plugin's data.json.
	githubPatSecretName: ""
};

/**
 * Halts the thread for a few milliseconds.
 * Extremely critical for Mobile OS to run Garbage Collection and prevent watchdog app kills.
 */
async function yieldThread(ms = 5) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * GitHub raw URLs serve a small text "pointer" file instead of the real
 * bytes when a file is tracked via Git LFS. Without this check that pointer
 * gets silently written to disk as if it were the real image/video/audio,
 * which is why media can look "installed" but is actually a broken/corrupt
 * few-hundred-byte stub. We detect it by reading the first bytes as text.
 */
function isLikelyLfsPointer(arrayBuffer) {
	if (!arrayBuffer || arrayBuffer.byteLength === 0 || arrayBuffer.byteLength > 1024) return false;
	try {
		const head = new TextDecoder('utf-8').decode(arrayBuffer.slice(0, 200));
		return head.startsWith('version https://git-lfs.github.com/spec');
	} catch (e) {
		return false;
	}
}

/**
 * Small retry wrapper for flaky mobile connections. Retries once after a
 * short backoff before giving up.
 */
async function withRetry(fn, retries = 1, delayMs = 400) {
	let lastErr;
	for (let attempt = 0; attempt <= retries; attempt++) {
		try {
			return await fn();
		} catch (e) {
			lastErr = e;
			if (attempt < retries) await yieldThread(delayMs);
		}
	}
	throw lastErr;
}

class InstallManagerModal extends Modal {
	constructor(app, plugin) {
		super(app);
		this.plugin = plugin;
		this.aborted = false;
		this.selectedPaths = new Set();
		this.filesToInstall = [];
		this.fileCheckboxMap = new Map();
		this.folderCheckboxMap = new Map();
	}

	async onOpen() {
		this.aborted = false;
		await this.fetchIndexAndShowTree();
	}

	onClose() {
		// If the user clicks outside or hits Esc, instantly kill any active downloads
		this.aborted = true; 
		this.contentEl.empty();
	}

	async fetchIndexAndShowTree() {
		const { contentEl, titleEl } = this;
		contentEl.empty();
		titleEl.setText('Fetching Notes...');

		const loadingEl = contentEl.createEl('div', { attr: { style: 'text-align: center; margin: 20px 0;' } });
		loadingEl.createEl('p', { text: 'Retrieving the latest index from GitHub...' });
		const spinner = loadingEl.createEl('progress', { attr: { style: 'width: 100%' } });
		spinner.removeAttribute('value');

		try {
			if (!this.plugin.latestVersion) {
				await this.plugin.fetchLatestVersion();
				if (!this.plugin.latestVersion) {
					throw new Error(this.plugin.versionFetchError || "Failed to find latest version.");
				}
			}

			const owner = this.plugin.settings.repositoryOwner;
			const repo = this.plugin.settings.repositoryName;
			const tag = this.plugin.latestVersion;
			const indexUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${tag}/vault-index.json`;
			
			const res = await requestUrl({ url: indexUrl, headers: this.plugin.getAuthHeaders() });
			const indexData = res.json;

			if (!indexData || !indexData.files || !Array.isArray(indexData.files)) {
				throw new Error("Invalid vault-index.json format.");
			}

			// Filter the incoming files by the Install and Preserve lists
			this.filesToInstall = indexData.files
				.map(f => f.path)
				.filter(path => this.plugin.isInstallAllowed(path) && !this.plugin.isPreserved(path));

			if (this.filesToInstall.length === 0) {
				throw new Error("No files found to install based on your settings.");
			}

			// By default, select everything allowed
			this.selectedPaths = new Set(this.filesToInstall);

			// Now show the Tree UI
			this.showTreeUi();

		} catch (error) {
			contentEl.empty();
			titleEl.setText('Error');
			contentEl.createEl('p', { text: error.message, attr: { style: 'color: var(--text-error);' } });
			const closeBtn = contentEl.createEl('button', { text: 'Close' });
			closeBtn.onclick = () => this.close();
		}
	}

	buildTree(filePaths) {
		const root = { name: '/', children: {}, isFolder: true, path: '/' };
		for (const path of filePaths) {
			const parts = path.split('/');
			let curr = root;
			for (let i = 0; i < parts.length - 1; i++) {
				const folderName = parts[i];
				if (!curr.children[folderName]) {
					curr.children[folderName] = { 
						name: folderName, 
						children: {}, 
						isFolder: true, 
						path: parts.slice(0, i+1).join('/') 
					};
				}
				curr = curr.children[folderName];
			}
			const filename = parts[parts.length - 1];
			curr.children[filename] = { name: filename, isFolder: false, path: path };
		}
		return root;
	}

	updateFolderCheckboxes() {
		for (const [folderPath, folderData] of this.folderCheckboxMap.entries()) {
			const { cb, childPaths } = folderData;
			let checkedCount = 0;
			for (const p of childPaths) {
				if (this.selectedPaths.has(p)) checkedCount++;
			}
			
			if (checkedCount === 0) {
				cb.checked = false;
				cb.indeterminate = false;
			} else if (checkedCount === childPaths.length) {
				cb.checked = true;
				cb.indeterminate = false;
			} else {
				cb.checked = false;
				cb.indeterminate = true;
			}
		}
	}

	renderNode(container, node) {
		const row = container.createDiv({ attr: { style: 'display: flex; align-items: center; padding: 4px 0;' } });

		if (node.isFolder) {
			const details = container.createEl('details', { attr: { open: true, style: 'margin-left: 20px; width: 100%;' } });
			const summary = details.createEl('summary', { attr: { style: 'cursor: pointer; font-weight: bold; padding: 4px 0; list-style-position: inside; user-select: none;' } });

			const folderCb = summary.createEl('input', { type: 'checkbox', attr: { style: 'margin-right: 8px;' } });
			summary.createEl('span', { text: `📁 ${node.name}` });

			const childContainer = details.createDiv();

			// Gather all file paths under this folder
			const childPaths = [];
			const gatherPaths = (n) => {
				if (!n.isFolder) childPaths.push(n.path);
				else Object.values(n.children).forEach(gatherPaths);
			};
			gatherPaths(node);

			this.folderCheckboxMap.set(node.path, { cb: folderCb, childPaths });

			// A click on a checkbox nested inside <summary> bubbles up and
			// triggers the browser's native details toggle, so tapping the
			// checkbox also expands/collapses the folder. Stop it there.
			folderCb.onclick = (e) => e.stopPropagation();

			folderCb.onchange = (e) => {
				const isChecked = e.target.checked;
				for (const p of childPaths) {
					if (isChecked) this.selectedPaths.add(p);
					else this.selectedPaths.delete(p);
					
					const fileCb = this.fileCheckboxMap.get(p);
					if (fileCb) fileCb.checked = isChecked;
				}
				this.updateFolderCheckboxes();
			};

			// Render children sorted alphabetically
			const childKeys = Object.keys(node.children).sort();
			for (const key of childKeys) {
				this.renderNode(childContainer, node.children[key]);
			}
		} else {
			const cb = row.createEl('input', { type: 'checkbox', attr: { style: 'margin-right: 8px; margin-left: 20px;' } });
			cb.checked = this.selectedPaths.has(node.path);
			this.fileCheckboxMap.set(node.path, cb);

			const label = row.createEl('span', { text: `📄 ${node.name}`, attr: { style: 'cursor: pointer;' } });
			
			const toggleFile = () => {
				if (this.selectedPaths.has(node.path)) {
					this.selectedPaths.delete(node.path);
					cb.checked = false;
				} else {
					this.selectedPaths.add(node.path);
					cb.checked = true;
				}
				this.updateFolderCheckboxes();
			};

			cb.onchange = toggleFile;
			label.onclick = toggleFile;
		}
	}

	showTreeUi() {
		const { contentEl, titleEl } = this;
		contentEl.empty();
		titleEl.setText('Review Installation');

		const sectionDiv = contentEl.createDiv({ attr: { style: 'margin-bottom: 25px;' } });

		// Header matching the requested design
		const headerFlex = sectionDiv.createDiv({ attr: { style: 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 5px;' } });
		headerFlex.createEl('h3', { text: 'Files to Install', attr: { style: 'margin: 0;' } });
		
		const controlsDiv = headerFlex.createDiv({ attr: { style: 'display: flex; gap: 20px; align-items: center;' } });

		// Expand All Toggle
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

		// Select All Toggle
		const selectAllDiv = controlsDiv.createDiv({ attr: { style: 'display: flex; align-items: center; gap: 8px;' } });
		selectAllDiv.createEl('span', { text: 'Select All', cls: 'text-muted', attr: { style: 'font-size: 0.9em; user-select: none;' } });
		new ToggleComponent(selectAllDiv)
			.setValue(true) 
			.onChange((value) => {
				for (const path of this.filesToInstall) {
					if (value) this.selectedPaths.add(path);
					else this.selectedPaths.delete(path);
					
					const cb = this.fileCheckboxMap.get(path);
					if (cb) cb.checked = value;
				}
				this.updateFolderCheckboxes();
			});

		const treeContainer = sectionDiv.createDiv({ attr: { style: 'max-height: 50vh; overflow-y: auto; background: var(--background-secondary); padding: 15px; border-radius: 5px; border: 1px solid var(--background-modifier-border);' } });
		
		const tree = this.buildTree(this.filesToInstall);
		const rootKeys = Object.keys(tree.children).sort();
		for (const key of rootKeys) {
			this.renderNode(treeContainer, tree.children[key]);
		}

		this.updateFolderCheckboxes();

		const btnContainer = contentEl.createDiv({ attr: { style: 'display: flex; justify-content: flex-end; gap: 10px; margin-top: 15px;' } });
		
		const cancelBtn = btnContainer.createEl('button', { text: 'Cancel' });
		cancelBtn.onclick = () => this.close();

		const confirmBtn = btnContainer.createEl('button', { text: 'Start Installing', cls: 'mod-cta' });
		confirmBtn.onclick = async () => {
			if (this.selectedPaths.size === 0) {
				new Notice("No files selected.");
				return;
			}
			await this.startInstallation();
		};
	}

	async ensureDirectory(adapter, dirPath) {
		const parts = dirPath.split('/');
		let current = '';
		for (const part of parts) {
			current = current ? current + '/' + part : part;
			if (!(await adapter.exists(current))) {
				try { await adapter.mkdir(current); } catch (e) {}
			}
		}
	}

	async startInstallation() {
		this.contentEl.empty();
		this.titleEl.setText('Installing Notes...');

		const uiContainer = this.contentEl.createDiv({
			attr: {
				style: 'display: flex; flex-direction: column; gap: 15px;'
			}
		});

		const statusContainer = uiContainer.createDiv({
			attr: {
				style: 'text-align: center; margin-bottom: 10px;'
			}
		});

		const statusTitle = statusContainer.createEl('div', {
			text: 'Initializing...',
			attr: {
				style: 'font-weight: bold; font-size: 1.1em; margin-bottom: 15px;'
			}
		});

		const statusCount = statusContainer.createEl('div', {
			attr: {
				style: 'font-size: 1.2em; font-weight: bold; margin-bottom: 15px;'
			}
		});

		const statusCurrentLabel = statusContainer.createEl('div', {
			attr: {
				style: 'font-size: 0.9em; color: var(--text-muted);'
			}
		});

		const statusCurrentPath = statusContainer.createEl('div', {
			attr: {
				style: 'font-size: 0.85em; color: var(--text-accent); word-break: break-all; min-height: 2.5em; margin-top: 5px;'
			}
		});

		const progressEl = uiContainer.createEl('progress', {
			attr: {
				style: 'width: 100%',
				value: 0,
				max: 100
			}
		});

		const btnContainer = uiContainer.createDiv({
			attr: {
				style: 'display: flex; justify-content: center; margin-top: 15px;'
			}
		});

		const stopBtn = btnContainer.createEl('button', {
			text: 'Stop Installing',
			cls: 'mod-warning'
		});

		stopBtn.onclick = () => {
			this.aborted = true;
			stopBtn.disabled = true;
			stopBtn.innerText = 'Stopping...';
		};

		const adapter = this.app.vault.adapter;
		const owner = this.plugin.settings.repositoryOwner;
		const repo = this.plugin.settings.repositoryName;
		const tag = this.plugin.latestVersion;

		try {
			// ============================================================
			// PHASE 1: DOWNLOAD
			// ============================================================

			statusTitle.innerText = 'Downloading notes...';
			statusCurrentLabel.innerText = 'Current:';

			let downloadedCount = 0;
			const failedFiles = [];

			const pathsToProcess = Array.from(this.selectedPaths);

			for (let i = 0; i < pathsToProcess.length; i++) {
				if (this.aborted) break;

				const targetPath = pathsToProcess[i];

				statusCount.innerText = `${i + 1} / ${pathsToProcess.length}`;
				statusCurrentPath.innerText = targetPath;
				progressEl.value =
					((i + 1) / pathsToProcess.length) * 100;

				try {
					const urlPath = targetPath
						.split('/')
						.map(encodeURIComponent)
						.join('/');

					const fileUrl =
						`https://raw.githubusercontent.com/${owner}/${repo}/${tag}/${urlPath}`;

					const res = await withRetry(() =>
						requestUrl({
							url: fileUrl,
							headers: this.plugin.getAuthHeaders()
						})
					);

					if (!res.arrayBuffer || res.arrayBuffer.byteLength === 0) {
						throw new Error("Empty response from GitHub.");
					}

					if (isLikelyLfsPointer(res.arrayBuffer)) {
						throw new Error(
							"This file is stored via Git LFS — raw.githubusercontent.com only serves a pointer stub for it, not the real bytes. Host it as a normal (non-LFS) file in the repo to install it."
						);
					}

					const parts = targetPath.split('/');
					parts.pop();

					if (parts.length > 0) {
						await this.ensureDirectory(
							adapter,
							parts.join('/')
						);
					}

					// Overwrite existing file only after a successful download.
					await adapter.writeBinary(
						targetPath,
						res.arrayBuffer
					);

					downloadedCount++;

				} catch (e) {
					console.error(
						`[GATE Manager] Failed to download: ${targetPath}`,
						e
					);

					failedFiles.push({
						path: targetPath,
						reason: e.message || String(e)
					});
				}

				// Yield to prevent watchdog timeout on Mobile.
				await yieldThread(5);
			}

			// User manually stopped installation.
			if (this.aborted) {
				throw new Error("Installation stopped by user.");
			}

			// ============================================================
			// IMPORTANT:
			// If ANY download failed, do NOT prune old files and do NOT
			// mark this version as installed.
			// ============================================================

			if (failedFiles.length > 0) {
				stopBtn.style.display = 'none';

				statusTitle.innerText = 'Installation incomplete';
				statusTitle.style.color = 'var(--text-warning)';

				statusCount.innerText =
					`${downloadedCount} installed, ${failedFiles.length} failed.`;

				statusCurrentLabel.innerText = '';

				const preview = failedFiles
					.slice(0, 5)
					.map(f => `${f.path} — ${f.reason}`)
					.join('\n');

				statusCurrentPath.innerText =
					`⚠️ Some files could not be downloaded:\n` +
					`${preview}` +
					`${failedFiles.length > 5 ? '\n...' : ''}`;

				statusCurrentPath.style.color =
					'var(--text-warning)';

				progressEl.value =
					(downloadedCount / pathsToProcess.length) * 100;

				new Notice(
					`GATE Vault installation incomplete: ${failedFiles.length} file(s) failed.`
				);

				const closeBtn = uiContainer.createEl('button', {
					text: 'Close',
					cls: 'mod-cta'
				});

				closeBtn.onclick = () => this.close();

				return;
			}

			// ============================================================
			// PHASE 2: PRUNE ORPHANED FILES
			// Only happens when ALL selected downloads succeeded.
			// ============================================================

			statusTitle.innerText = 'Removing old files...';
			statusCurrentLabel.innerText = '';
			statusCurrentPath.innerText = '';

			const allFiles = this.app.vault.getFiles();
			let deletedCount = 0;

			for (let i = 0; i < allFiles.length; i++) {
				if (this.aborted) break;

				const file = allFiles[i];

				if (i % 20 === 0) {
					statusCount.innerText =
						`${deletedCount} removed`;

					await yieldThread(5);
				}

				if (!this.plugin.isInstallAllowed(file.path)) {
					continue;
				}

				if (this.plugin.isPreserved(file.path)) {
					continue;
				}

				// Anything still present in the current index is kept.
				if (this.filesToInstall.includes(file.path)) {
					continue;
				}

				await this.app.vault.delete(file, true);
				deletedCount++;
			}

			if (this.aborted) {
				throw new Error("Installation stopped by user.");
			}

			// ============================================================
			// PHASE 3: COMMIT SUCCESS
			// ============================================================

			this.plugin.settings.installedVersion =
				this.plugin.latestVersion;

			await this.plugin.saveSettings();
			this.plugin.notifyUI();

			stopBtn.style.display = 'none';

			statusTitle.innerText = 'Success!';
			statusTitle.style.color = 'var(--text-success)';

			statusCount.innerText =
				`${downloadedCount} files installed.`;

			statusCurrentLabel.innerText = '';

			statusCurrentPath.innerText =
				`Removed ${deletedCount} orphaned file(s).`;

			statusCurrentPath.style.color =
				'var(--text-muted)';

			progressEl.value = 100;

			new Notice(
				"GATE Vault installed successfully!"
			);

			const closeBtn = uiContainer.createEl('button', {
				text: 'Close',
				cls: 'mod-cta'
			});

			closeBtn.onclick = () => this.close();

		} catch (error) {

			if (error.message === "Installation stopped by user.") {
				console.log(
					"[GATE Manager] Installation was cleanly aborted by the user."
				);
			} else {
				console.error(
					"[GATE Manager] Installation Error:",
					error
				);
			}

			stopBtn.style.display = 'none';

			statusTitle.innerText =
				this.aborted ? 'Aborted' : 'Error';

			statusTitle.style.color =
				this.aborted
					? 'var(--text-warning)'
					: 'var(--text-error)';

			statusCount.innerText = '';
			statusCurrentLabel.innerText = '';

			statusCurrentPath.innerText =
				error.message;

			statusCurrentPath.style.color =
				this.aborted
					? 'var(--text-warning)'
					: 'var(--text-error)';

			progressEl.style.display = 'none';

			const closeBtn = uiContainer.createEl('button', {
				text: 'Close'
			});

			closeBtn.onclick = () => this.close();
		}
	}
}

class GateManagerView extends ItemView {
	constructor(leaf, plugin) {
		super(leaf);
		this.plugin = plugin;
		this.uiCallback = () => this.renderContent();
	}

	getViewType() { return VIEW_TYPE_GATE_MANAGER; }
	getDisplayText() { return "GATE Dashboard"; }
	getIcon() { return "library"; }

	async onOpen() {
		this.plugin.registerUICallback(this.uiCallback);
		if (!this.plugin.latestVersion) {
			await this.plugin.fetchLatestVersion();
		}
		this.renderContent();
	}

	async onClose() {
		this.plugin.unregisterUICallback(this.uiCallback);
	}

	renderContent() {
		const container = this.contentEl;
		container.empty();
		
		const mainContainer = container.createDiv({ 
			attr: { style: 'max-width: 600px; margin: 0 auto; padding: 2rem 1rem; text-align: center;' } 
		});

		mainContainer.createEl('h2', { text: 'GATE Dashboard', attr: { style: 'margin-bottom: 0.5rem;' } });
		mainContainer.createEl('p', { text: 'Directly download the latest community notes.', cls: 'text-muted' });

		const statusCard = mainContainer.createDiv({ attr: { style: 'border: 1px solid var(--background-modifier-border); border-radius: 8px; padding: 1.5rem; margin: 2rem 0; background: var(--background-secondary); text-align: left;' } });
		statusCard.createEl('h3', { text: 'Vault Status', attr: { style: 'margin-top: 0; border-bottom: 1px solid var(--background-modifier-border); padding-bottom: 0.5rem;' } });
		
		const statusGrid = statusCard.createDiv({ attr: { style: 'display: grid; grid-template-columns: auto 1fr; gap: 10px 20px; align-items: center;' } });
		const addRow = (label, value, isHighlight = false) => {
			statusGrid.createDiv({ text: label, cls: 'text-muted', attr: { style: 'font-weight: 400;' } });
			const valEl = statusGrid.createDiv({ text: value });
			if (isHighlight) valEl.style.color = 'var(--text-accent)';
		};

		addRow("Installed Version:", this.plugin.settings.installedVersion);
		addRow("Latest Available:", this.plugin.latestVersion || (this.plugin.versionFetchError ? "Unavailable" : "Fetching..."), true);

		if (!this.plugin.latestVersion && this.plugin.versionFetchError) {
			mainContainer.createEl('p', {
				text: this.plugin.versionFetchError,
				attr: { style: 'color: var(--text-error); font-size: 0.9em;' }
			});
		}

		const btn = mainContainer.createEl('button', { text: 'Install Notes', cls: 'mod-cta', attr: { style: 'padding: 10px 24px; font-size: 1.1em; border-radius: 6px;' } });
		btn.onclick = () => {
			new InstallManagerModal(this.app, this.plugin).open();
		};

		if (!this.plugin.latestVersion) {
			btn.disabled = true;
			btn.innerText = this.plugin.versionFetchError ? "Retry" : "Connecting...";
			if (this.plugin.versionFetchError) {
				btn.disabled = false;
				btn.onclick = async () => {
					btn.disabled = true;
					btn.innerText = "Connecting...";
					await this.plugin.fetchLatestVersion();
				};
			}
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

		// SECTION: Repository Info (Read-only)
		new Setting(containerEl).setHeading().setName('Repository Details');

		new Setting(containerEl)
			.setName('Latest Vault Version')
			.setDesc('Fetched directly from GitHub.')
			.addText(text => text.setDisabled(true).setValue(this.plugin.latestVersion || 'Fetching...'));

		new Setting(containerEl)
			.setName('Vault Username')
			.setDesc('The GitHub username/organization.')
			.addText(text => text.setDisabled(true).setValue(this.plugin.settings.repositoryOwner));

		new Setting(containerEl)
			.setName('Vault Repo Name')
			.setDesc('The repository containing the vault.')
			.addText(text => text.setDisabled(true).setValue(this.plugin.settings.repositoryName));

		// SECTION: Authentication (Optional)
		new Setting(containerEl).setHeading().setName('Authentication (Optional)');

		new Setting(containerEl)
			.setName('GitHub Personal Access Token')
			.setDesc('Optional, but recommended. Raises GitHub\'s rate limit from 60 to 5,000 requests/hour and is required if the vault repo is private. Stored securely via Obsidian\'s SecretStorage — never written to this plugin\'s data.json.')
			.addComponent(el => new SecretComponent(this.app, el)
				.setValue(this.plugin.settings.githubPatSecretName)
				.onChange(async (value) => {
					this.plugin.settings.githubPatSecretName = value;
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName('How to generate a token')
			.setDesc('Short walkthrough on creating a GitHub Personal Access Token.')
			.addButton(btn => btn
				.setButtonText('Watch Video')
				.onClick(() => window.open('https://youtu.be/zXPq0vc7DHs', '_blank'))
			);

		// SECTION: Installation & Preservation
		new Setting(containerEl).setHeading().setName('Installation & Protection Setup');

		new Setting(containerEl)
			.setName('Folders/Files to Install')
			.setDesc('Comma-separated list of paths to extract from the update. Leave entirely blank to install EVERYTHING from the repository.')
			.addTextArea(text => {
				text
					.setPlaceholder('e.g., GATE Notes, Images, specific_file.md')
					.setValue(this.plugin.settings.installList)
					.onChange(async (value) => {
						this.plugin.settings.installList = value;
						await this.plugin.saveSettings();
					});
				text.inputEl.rows = 3;
				text.inputEl.cols = 40;
				return text;
			});

		new Setting(containerEl)
			.setName('Do Not Touch these folders/files')
			.setDesc('Comma-separated list of paths to ALWAYS preserve. These will never be deleted or overwritten under any condition.')
			.addTextArea(text => {
				text
					.setPlaceholder('.obsidian, My Notes, private.md')
					.setValue(this.plugin.settings.preserveList)
					.onChange(async (value) => {
						this.plugin.settings.preserveList = value;
						await this.plugin.saveSettings();
					});
				text.inputEl.rows = 3;
				text.inputEl.cols = 40;
				return text;
			});

		// SECTION: Quick Actions
		new Setting(containerEl).setHeading().setName('Actions');

		new Setting(containerEl)
			.setName('Open Dashboard')
			.setDesc('Open the GATE Manager interface to install updates.')
			.addButton(btn => btn
				.setButtonText('Open Manager')
				.setCta()
				.onClick(() => {
					this.plugin.app.setting.close();
					this.plugin.openManager();
				})
			);

		new Setting(containerEl)
			.setName('Verify Archive Integrity')
			.setDesc('View the source repository to verify published assets.')
			.addButton(btn => btn
				.setButtonText('Verify Now')
				.onClick(() => {
					window.open(`https://github.com/${this.plugin.settings.repositoryOwner}/${this.plugin.settings.repositoryName}`, '_blank');
				})
			);

		new Setting(containerEl)
			.setName('Clear Cache')
			.setDesc('Cleans any legacy background temporary files.')
			.addButton(button => button
				.setButtonText('Clear Cache')
				.setWarning()
				.onClick(async () => {
					await this.plugin.clearCache();
				})
			);

		// SECTION: Socials & Support
		new Setting(containerEl).setHeading().setName('Community & Support');

		const socialSetting = new Setting(containerEl)
			.setName('Connect with us')
			.setDesc('Reach out via official channels for updates and announcements.');

		socialSetting.addButton(btn => btn
			.setButtonText('YouTube')
			.onClick(() => window.open('https://www.youtube.com/@zettelforgate', '_blank'))
		);
		socialSetting.addButton(btn => btn
			.setButtonText('Telegram')
			.onClick(() => window.open('https://t.me/gate_ee0', '_blank'))
		);
		socialSetting.addButton(btn => btn
			.setButtonText('Email')
			.onClick(() => window.open('mailto:zettelforgate@gmail.com', '_blank'))
		);

		new Setting(containerEl)
			.setName('Support the Creator')
			.setDesc('If you find this plugin helpful for your studies, consider supporting its development.')
			.addButton(btn => btn
				.setButtonText('Contribution')
				.setCta()
				.onClick(() => window.open('https://razorpay.me/@anandbaghel', '_blank'))
			);
	}
}

class GateManagerPlugin extends Plugin {
	async onload() {
		await this.loadSettings();
		
		this.latestVersion = null;
		this.versionFetchError = null;
		this.uiRefreshCallbacks = [];

		this.registerView(VIEW_TYPE_GATE_MANAGER, (leaf) => new GateManagerView(leaf, this));

		this.addRibbonIcon('library', 'GATE Manager', () => this.openManager());
		this.addCommand({ id: 'open-gate-manager', name: 'Open GATE Manager', callback: () => this.openManager() });
		this.addSettingTab(new GateManagerSettingTab(this.app, this));

		// Fetch latest release data quietly on load
		this.fetchLatestVersion();
	}

	onunload() {
		new Notice("GATE Manager unloaded");
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	registerUICallback(cb) { this.uiRefreshCallbacks.push(cb); }
	unregisterUICallback(cb) { this.uiRefreshCallbacks = this.uiRefreshCallbacks.filter(func => func !== cb); }

	notifyUI() {
		for (const cb of this.uiRefreshCallbacks) cb();
	}

	showNotice(msg) {
		new Notice(msg);
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

	/**
	 * Resolves the actual token via SecretStorage using the name saved in
	 * settings, and returns headers ready to spread into a requestUrl call.
	 * Returns {} if no token is configured or SecretStorage isn't available
	 * (older Obsidian versions), so everything still works unauthenticated.
	 */
	getAuthHeaders() {
		if (!this.app.secretStorage || !this.settings.githubPatSecretName) return {};
		try {
			const token = this.app.secretStorage.getSecret(this.settings.githubPatSecretName);
			return token ? { Authorization: `Bearer ${token}` } : {};
		} catch (e) {
			console.warn("[GATE Manager] Could not read GitHub token from SecretStorage:", e);
			return {};
		}
	}

	async fetchLatestVersion() {
		this.versionFetchError = null;
		try {
			const res = await requestUrl({
				url: `https://api.github.com/repos/${this.settings.repositoryOwner}/${this.settings.repositoryName}/releases/latest`,
				headers: { 'User-Agent': 'Obsidian-Gate-Manager', ...this.getAuthHeaders() },
				throw: false
			});

			if (res.status === 200) {
				this.latestVersion = res.json.tag_name;
			} else if (res.status === 403 || res.status === 429) {
				this.versionFetchError = this.settings.githubPatSecretName
					? "GitHub's request limit was hit even with a token set — double check the token is valid in Settings."
					: "GitHub's request limit was hit for your network (shared wifi/campus networks run into this fast). Adding a GitHub token in Settings raises this limit a lot. Otherwise, wait a bit and try again.";
				console.warn("[GATE Manager] GitHub rate limit hit while fetching latest release.");
			} else if (res.status === 404) {
				this.versionFetchError = "No published release found for this repository.";
			} else {
				this.versionFetchError = `GitHub returned an unexpected status (${res.status}) while checking for the latest version.`;
			}
		} catch (error) {
			this.versionFetchError = "Could not reach GitHub. Check your internet connection and try again.";
			console.error("[GATE Manager] Failed to fetch latest release:", error);
		}
		this.notifyUI();
	}

	isInstallAllowed(path) {
		// Always allow .nomedia files so Android doesn't scan vault images into the system gallery
		if (path === '.nomedia' || path.endsWith('/.nomedia')) return true;

		if (!this.settings.installList) return true;
		
		const installList = this.settings.installList.split(',').map(s => s.trim()).filter(Boolean);
		if (installList.length === 0) return true; 
		
		for (const p of installList) {
			if (path === p || path.startsWith(p + '/')) {
				return true;
			}
		}
		return false;
	}

	isPreserved(path) {
		// Strict hardcoded protections
		if (path.startsWith('.obsidian/') || path.startsWith('.trash/')) return true;

		if (!this.settings.preserveList) return false;

		const preserved = this.settings.preserveList.split(',').map(s => s.trim()).filter(Boolean);
		for (const p of preserved) {
			if (path === p || path.startsWith(p + '/')) {
				return true;
			}
		}
		return false;
	}

	async clearCache() {
		// Just cleans up legacy temp folders from older ZIP-based plugin versions if they exist
		const legacyTemp = ".obsidian/plugins/gate-manager/temp";
		if (await this.app.vault.adapter.exists(legacyTemp)) {
			try {
				await this.app.vault.adapter.rmdir(legacyTemp, true);
				new Notice("Legacy background cache cleared successfully.");
			} catch(e) {
				console.warn("Could not completely delete legacy cache directory.", e);
				new Notice("Cache partially cleared.");
			}
		} else {
			new Notice("Cache is already empty.");
		}
	}
}

module.exports = GateManagerPlugin;
