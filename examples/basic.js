// node examples/basic.js [file.js]
// Uses the bundled WebAssembly parser and prints the compressed IR.
const fs = require("node:fs");
const { analyzeAsync, compress } = require("..");

const file = process.argv[2] || __filename;
let code;
try {
  code = fs.readFileSync(file, "utf8");
} catch (error) {
  console.error(`basic.js: cannot read ${file} (${error.code || error.message})`);
  console.error("usage: node node_modules/sentinel-ir/examples/basic.js <file>");
  process.exit(1);
}

async function main() {
  const ir = compress(await analyzeAsync(code, { target: file }));
  const json = JSON.stringify(ir);

  console.log(JSON.stringify(ir, null, 2));
  console.error(`raw: ${code.length} chars, IR: ${json.length} chars`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
