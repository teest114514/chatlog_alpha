import "./ply_exec.js";

let wasmModule;
async function ply(doc, format) {
	const go = new Ply();
	if (typeof(wasmModule) === "undefined") {
		let plyWasm = fetch("ply.wasm");
		await WebAssembly.compileStreaming(plyWasm).then(m => {
			wasmModule = m;
		})
	}
	return WebAssembly.instantiate(wasmModule, go.importObject).then(inst => {
		return go.run(inst, Uint8Array.from(doc), format);
	});
}

var encoder;
var decoder;

async function toU8(string) {
	if (typeof(encoder) === "undefined") {
		encoder = new TextEncoder("utf-8");
	}
	return encoder.encode(string);
}

async function fromU8(buf) {
	if (typeof(decoder) === "undefined") {
		decoder = new TextDecoder("utf-8");
	}
	return decoder.decode(buf);
}

export function convertDocument() {
	let outTextField = document.getElementById("plistOut");
	outTextField.value = "(loading, hold on. first time's slow.)";
	toU8(document.getElementById("plistIn").value).then(plistDocument => {
		return ply(plistDocument, document.getElementById("plistConvertTo").value);
	}).then(out => {
		return fromU8(out)
	}).then(out => {
		outTextField.value = out;
	}).catch(err => {
		outTextField.value = "FAILED!\n" + err;
	});
}