// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	const diagnosticCollection = vscode.languages.createDiagnosticCollection('dockerfile');
	
	context.subscriptions.push(diagnosticCollection);

	if (vscode.window.activeTextEditor) {
		updateDiagnostics(vscode.window.activeTextEditor.document, diagnosticCollection);
	}
	context.subscriptions.push(
		vscode.window.onDidChangeActiveTextEditor(editor => {
			if (editor) {
				updateDiagnostics(editor.document, diagnosticCollection);
			}
		})
	);

	context.subscriptions.push(
		vscode.workspace.onDidChangeTextDocument(e => updateDiagnostics(e.document, diagnosticCollection))
	);

	context.subscriptions.push(
		vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri))
	);
}

// This method is called when your extension is deactivated
export function deactivate() {}

function updateDiagnostics(document: vscode.TextDocument, collection: vscode.DiagnosticCollection): void {
	if (document && path.basename(document.uri.fsPath) === 'sample-demo.rs') {
		collection.set(document.uri, [{
			code: '',
			message: 'cannot assign twice to immutable variable `x`',
			range: new vscode.Range(new vscode.Position(3, 4), new vscode.Position(3, 10)),
			severity: vscode.DiagnosticSeverity.Error,
			source: '',
			relatedInformation: [
				new vscode.DiagnosticRelatedInformation(new vscode.Location(document.uri, new vscode.Range(new vscode.Position(1, 8), new vscode.Position(1, 9))), 'first assignment to `x`')
			]
		}]);
	} else {
		collection.clear();
	}
}
