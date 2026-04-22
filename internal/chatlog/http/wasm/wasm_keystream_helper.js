const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function initWasm(basePath) {
  const wasmPath = path.join(basePath, 'wasm_video_decode.wasm');
  const jsPath = path.join(basePath, 'wasm_video_decode.js');
  const wasmBinary = fs.readFileSync(wasmPath);
  let capturedKeystream = null;

  return await new Promise((resolve, reject) => {
    try {
      const mockGlobal = {
        console,
        Buffer,
        Uint8Array,
        Int8Array,
        Uint16Array,
        Int16Array,
        Uint32Array,
        Int32Array,
        Float32Array,
        Float64Array,
        BigInt64Array,
        BigUint64Array,
        Array,
        Object,
        Function,
        String,
        Number,
        Boolean,
        Error,
        Promise,
        require,
        process,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
      };

      mockGlobal.Module = {
        onRuntimeInitialized: () => resolve({
          Module: mockGlobal.Module,
          getCapturedKeystream: () => capturedKeystream,
          resetCapturedKeystream: () => { capturedKeystream = null; }
        }),
        wasmBinary,
        print: () => {},
        printErr: (...args) => console.error(...args),
      };

      mockGlobal.self = mockGlobal;
      mockGlobal.self.location = { href: jsPath };
      mockGlobal.WorkerGlobalScope = function () {};
      mockGlobal.VTS_WASM_URL = `file://${wasmPath}`;
      mockGlobal.wasm_isaac_generate = (ptr, size) => {
        const buf = new Uint8Array(mockGlobal.Module.HEAPU8.buffer, ptr, size);
        capturedKeystream = new Uint8Array(buf);
      };

      const jsContent = fs.readFileSync(jsPath, 'utf8');
      const script = new vm.Script(jsContent, { filename: jsPath });
      const context = vm.createContext(mockGlobal);
      script.runInContext(context);
    } catch (error) {
      reject(error);
    }
  });
}

async function getRawKeystream(runtime, key, size) {
  const mod = runtime.Module;
  if (!mod.WxIsaac64 && mod.asm && mod.asm.WxIsaac64) {
    mod.WxIsaac64 = mod.asm.WxIsaac64;
  }
  if (!mod.WxIsaac64) {
    throw new Error('WxIsaac64 not found in WASM module');
  }
  runtime.resetCapturedKeystream();
  const isaac = new mod.WxIsaac64(key);
  isaac.generate(size);
  if (isaac.delete) isaac.delete();
  const ks = runtime.getCapturedKeystream();
  if (!ks) {
    throw new Error('Failed to capture keystream');
  }
  return Buffer.from(ks);
}

async function main() {
  const key = String(process.argv[2] || '').trim();
  const requested = Number.parseInt(String(process.argv[3] || '131072'), 10);
  const mode = String(process.argv[4] || 'reversed').trim().toLowerCase();
  if (!key) {
    throw new Error('Missing key');
  }
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error('Invalid size');
  }
  const alignSize = Math.ceil(requested / 8) * 8;
  const runtime = await initWasm(__dirname);
  const raw = await getRawKeystream(runtime, key, alignSize);
  let out;
  if (mode === 'raw') {
    out = Buffer.from(raw).subarray(0, requested);
  } else {
    const reversed = Buffer.from(raw);
    reversed.reverse();
    out = reversed.subarray(0, requested);
  }
  process.stdout.write(out.toString('base64'));
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
