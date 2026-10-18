// node examples/basic.js [file.js]
// Uses the bundled WebAssembly parser and prints the compressed IR.
const fs = require("node:fs");
const { analyzeAsync, compress } = require("..");

const file = process.argv[2] || __filename;
const code = fs.readFileSync(file, "utf8");

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
