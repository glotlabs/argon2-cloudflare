import assert from "node:assert/strict";

const base = process.argv[2] ?? "http://127.0.0.1:8787";

async function post(path, body, status = 200) {
  const response = await fetch(new URL(path, base), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  assert.equal(response.status, status, text);
  return status === 200 ? JSON.parse(text) : text;
}

const password = "dependency upgrade test 🔑";
const first = await post("/hash", { password });
const second = await post("/hash", { password });
assert.match(first.hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
assert.notEqual(first.hash.split("$")[4], second.hash.split("$")[4]);
assert.deepEqual(await post("/verify", { password, hash: first.hash }), { matches: true });
assert.deepEqual(await post("/verify", { password: "wrong", hash: first.hash }), { matches: false });

const custom = await post("/hash", {
  password,
  options: { memoryCost: 1024, timeCost: 3, parallelism: 2 },
});
assert.match(custom.hash, /^\$argon2id\$v=19\$m=1024,t=3,p=2\$/);
assert.deepEqual(await post("/verify", { password, hash: custom.hash }), { matches: true });

// Published Argon2 0.5.3 test vector: existing hashes must remain verifiable.
const legacyHash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
assert.deepEqual(await post("/verify", { password: "password", hash: legacyHash }), { matches: true });
await post("/verify", { password, hash: "invalid" }, 400);
await post("/hash", { password, options: { memoryCost: 0, timeCost: 0, parallelism: 0 } }, 400);
await post("/hash", {}, 400);
await post("/missing", {}, 404);
console.log("Worker smoke tests passed");
