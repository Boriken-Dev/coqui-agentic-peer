// coqui-peer-noise's JavaScript module as a joiner, for the pairing test. Frames on standard input and output are a
// little-endian u32 length, then a connection number byte and the message: 0 is the pairing connection, 1 the one after
// it, as two sockets would be. The first frame on 0 is the PIN to type. It pairs, then proves itself on 1 as an ordinary
// initiator pinned to the key it paired with, and exchanges one sealed message each way.
import {pathToFileURL} from 'node:url';

const [modulePath, mode] = process.argv.slice(2);
const {createInitiator, createPairingInitiator, generateIdentity} = await import(pathToFileURL(modulePath).href);

const inboxes = [[], []];
const waiters = [null, null];
let held = Buffer.alloc(0);
let ended = false;
process.stdin.on('data', (chunk) => {
  held = Buffer.concat([held, chunk]);
  while (held.length >= 4) {
    const length = held.readUInt32LE(0);
    if (held.length < 4 + length) break;
    const connection = held[4];
    const body = new Uint8Array(held.subarray(5, 4 + length));
    held = held.subarray(4 + length);
    if (waiters[connection]) {
      const take = waiters[connection];
      waiters[connection] = null;
      take(body);
    } else {
      inboxes[connection].push(body);
    }
  }
});
process.stdin.on('end', () => {
  ended = true;
  for (const wait of waiters) wait?.(null);
});
const on = (connection) => ({
  recv: () => new Promise((resolve) => {
    if (inboxes[connection].length) resolve(inboxes[connection].shift());
    else if (ended) resolve(null);
    else waiters[connection] = resolve;
  }),
  send: async (bytes) => {
    const framed = Buffer.alloc(5 + bytes.length);
    framed.writeUInt32LE(1 + bytes.length, 0);
    framed[4] = connection;
    Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).copy(framed, 5);
    await new Promise((resolve, reject) => process.stdout.write(framed, (error) => (error ? reject(error) : resolve())));
  },
});
const text = (bytes) => new TextDecoder().decode(bytes);

const identity = await generateIdentity();
const first = on(0);
let pin = text(await first.recv());
if (mode === 'wrong') pin = pin === '000000' ? '000001' : '000000';

const near = await createPairingInitiator(identity);
await first.send(await near.hello());
const {reply, pairing} = await near.answer(await first.recv());
await first.send(reply);
let paired;
try {
  paired = await pairing.join(pin, first);
} catch (error) {
  process.stderr.write(`refused: ${error.refusal ?? error.message}\n`);
  process.exit(mode === 'wrong' && error.refusal === 'wrong-code' ? 0 : 1);
}
if (mode === 'wrong') process.exit(1);

const second = on(1);
const proof = await createInitiator(identity, paired.peerId);
await second.send(await proof.hello());
const proved = await proof.answer(await second.recv());
await second.send(proved.reply);
const {session} = proved;
await second.send(await session.seal(`hello from ${identity.peerId}`));
const answer = await session.open(await second.recv());
if (answer === null || text(answer) !== 'hello from rust') process.exit(1);
await second.send(await session.close());
session.destroy();
process.exit(0);
