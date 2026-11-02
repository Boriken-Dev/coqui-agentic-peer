import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { StreamEnded, createMux, decodeFrame, encodeFrame, startsMux, validProtocol } from '../src/mux.mjs';

const vectors = JSON.parse(readFileSync(new URL('../../../vectors/mux.json', import.meta.url), 'utf8'));
const unhex = (text) => Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
const text = (bytes) => new TextDecoder().decode(bytes);

test('the vectors are the wire', () => {
  for (const vector of vectors.frames) {
    const bytes = unhex(vector.hex);
    const frame = decodeFrame(bytes);
    assert.ok(frame, vector.name);
    assert.equal(frame.kind, vector.kind);
    assert.equal(frame.stream ?? 0, vector.stream ?? 0);
    if (vector.protocol !== undefined) assert.equal(frame.protocol, vector.protocol);
    if (vector.kind === 'open') assert.deepEqual([...frame.metadata], [...unhex(vector.metadata ?? '')]);
    if (vector.kind === 'close') assert.equal(frame.text, vector.text ?? '');
    if (vector.body !== undefined) assert.deepEqual([...frame.body], [...unhex(vector.body)]);
    if (vector.bytes !== undefined) assert.equal(frame.bytes, vector.bytes);
    if (vector.reason !== undefined) assert.equal(frame.reason, vector.reason);
    assert.deepEqual([...encodeFrame(frame)], [...bytes], vector.name);
  }
  for (const vector of vectors.invalid) assert.equal(decodeFrame(unhex(vector.hex)), null, vector.name);
});

test('the decoder takes any bytes without throwing, and what it takes encodes back to them', () => {
  let seed = 12345;
  const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  for (let round = 0; round < 20000; round += 1) {
    const bytes = Uint8Array.from({ length: next() % 16 }, () => (round % 2 === 0 ? next() % 5 : next() % 256));
    const frame = decodeFrame(bytes);
    if (frame !== null) assert.deepEqual([...encodeFrame(frame)], [...bytes]);
  }
});

test('a first message opening a mux is told from plain ACP', () => {
  assert.equal(startsMux(encodeFrame({ kind: 'open', stream: 1, protocol: 'acp/1' })), true);
  assert.equal(startsMux(new TextEncoder().encode('{"jsonrpc":"2.0"}')), false);
  assert.equal(startsMux(new Uint8Array()), false);
});

test('a protocol token can go in a record as it is', () => {
  for (const good of ['acp/1', 'a2a/1', 'mcp', 'tcp/1', 'dev.boriken.ai6/tether']) assert.ok(validProtocol(good), good);
  for (const bad of ['', 'a b', 'a,b', 'a=b', 'é', 'x'.repeat(65), 7]) assert.ok(!validProtocol(bad), String(bad));
});

/** Two ends in memory, delivering in order on later turns. */
function pair() {
  const end = () => ({ peer: null, listen: null, closeListen: null, sent: [] });
  const a = end();
  const b = end();
  a.peer = b;
  b.peer = a;
  const link = (self) => ({
    send: async (message) => {
      self.sent.push(message);
      setImmediate(() => self.peer.listen?.(message));
    },
    onMessage: (listen) => {
      self.listen = listen;
    },
    onClose: (listen) => {
      self.closeListen = listen;
    },
  });
  return { a, b, dialed: link(a), answered: link(b) };
}

const within = (promise, ms = 2000) => Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error('timed out')), ms))]);

test('two protocols run at once, each on its own stream', async () => {
  const { dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed' });
  const server = createMux(answered, { side: 'answered' });
  const acp = await client.open('acp/1');
  const mcp = await client.open('mcp');
  await acp.send('to acp');
  await mcp.send('to mcp');
  const first = await within(server.accept());
  const second = await within(server.accept());
  assert.deepEqual([first.protocol, second.protocol], ['acp/1', 'mcp']);
  assert.equal(text(await within(first.receive())), 'to acp');
  assert.equal(text(await within(second.receive())), 'to mcp');
  await first.send('acp says');
  assert.equal(text(await within(acp.receive())), 'acp says');
});

test('a stream that stops reading holds up only itself', async () => {
  const { dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed', limits: { window: 16 } });
  const server = createMux(answered, { side: 'answered', limits: { window: 16 } });
  const stuck = await client.open('stuck');
  const live = await client.open('live');
  const serverStuck = await within(server.accept());
  const serverLive = await within(server.accept());
  await stuck.send(new Uint8Array(32));
  let released = false;
  const waiting = stuck.send(new Uint8Array(8)).then(() => {
    released = true;
  });
  for (let round = 0; round < 50; round += 1) {
    await live.send(new Uint8Array(8).fill(round));
    assert.equal((await within(serverLive.receive()))[0], round);
  }
  assert.equal(released, false, 'the stuck stream has no credit');
  await within(serverStuck.receive());
  await within(waiting);
  assert.equal(released, true, 'reading gives credit back');
});

test('metadata reaches the side accepting, and each cause arrives as itself', async () => {
  for (const reason of ['refused', 'superseded', 'revoked']) {
    const { dialed, answered } = pair();
    const client = createMux(dialed, { side: 'dialed' });
    const server = createMux(answered, { side: 'answered' });
    const stream = await client.open('x', Uint8Array.of(42));
    const incoming = await within(server.accept());
    assert.deepEqual([...incoming.metadata], [42]);
    incoming.close(reason, 'because');
    await assert.rejects(within(stream.receive()), (error) => error instanceof StreamEnded && error.reason === reason && error.text === 'because');
  }
});

test('finishing ends one direction, and the answer still comes back', async () => {
  const { dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed' });
  const server = createMux(answered, { side: 'answered' });
  const stream = await client.open('a2a/1');
  await stream.send('request');
  await stream.finish();
  await assert.rejects(stream.send('more'), RangeError);
  const incoming = await within(server.accept());
  assert.equal(text(await within(incoming.receive())), 'request');
  assert.equal(await within(incoming.receive()), null, 'finished, not truncated');
  await incoming.send('answer');
  incoming.close();
  assert.equal(text(await within(stream.receive())), 'answer');
  assert.equal(await within(stream.receive()), null);
});

test('a long message arrives whole, cut into frames', async () => {
  const { a, dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed', limits: { maxFrame: 1024 } });
  const server = createMux(answered, { side: 'answered', limits: { maxFrame: 1024 } });
  const stream = await client.open('long');
  await stream.send(new Uint8Array(4096 + 10).fill(9));
  const incoming = await within(server.accept());
  const message = await within(incoming.receive());
  assert.equal(message.length, 4106);
  assert.ok(message.every((byte) => byte === 9));
  const kinds = a.sent.map((frame) => decodeFrame(frame).kind);
  assert.deepEqual(kinds, ['open', 'more', 'more', 'more', 'more', 'data']);
  assert.equal(await Promise.race([incoming.receive(), Promise.resolve('nothing yet')]), 'nothing yet');
});

test('parts past the largest message end the stream before they are held, and data after finish breaks it', async () => {
  const first = against({ maxMessage: 8 });
  first.frame({ kind: 'open', stream: 1, protocol: 'x' });
  first.frame({ kind: 'more', stream: 1, body: new Uint8Array(5) });
  first.frame({ kind: 'more', stream: 1, body: new Uint8Array(5) });
  await assert.rejects((await first.mux.accept()).receive(), (error) => error.reason === 'broken');
  const second = against();
  second.frame({ kind: 'open', stream: 1, protocol: 'x' });
  second.frame({ kind: 'finish', stream: 1 });
  second.frame({ kind: 'data', stream: 1, body: new Uint8Array(1) });
  await assert.rejects((await second.mux.accept()).receive(), (error) => error.reason === 'broken');
});

test('either side opens streams, whoever connected', async () => {
  const { dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed' });
  const server = createMux(answered, { side: 'answered' });
  const stream = await server.open('dev.boriken.ai6/tether');
  await stream.send('from the side that answered');
  const incoming = await within(client.accept());
  assert.equal(incoming.protocol, 'dev.boriken.ai6/tether');
  assert.equal(text(await within(incoming.receive())), 'from the side that answered');
});

test('trySend says full at once, and a link answering pings is not lost for a silent stream', async () => {
  const { dialed, answered } = pair();
  const heartbeat = { interval: 20, misses: 3 };
  const client = createMux(dialed, { side: 'dialed', limits: { window: 8, heartbeat } });
  const server = createMux(answered, { side: 'answered', limits: { window: 8, heartbeat } });
  const stream = await client.open('quiet');
  await within(server.accept());
  assert.equal(stream.trySend(new Uint8Array(8)), true);
  assert.equal(stream.trySend(new Uint8Array(1)), false);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(client.linkState().up, true);
});

test('a link gone silent is lost, and every stream hears why', async () => {
  const mux = createMux({ send: async () => {}, onMessage: () => {}, onClose: () => {} }, { side: 'dialed', limits: { heartbeat: { interval: 10, misses: 2 } } });
  const stream = await mux.open('x');
  await assert.rejects(within(stream.receive()), (error) => error.reason === 'link-lost');
  assert.equal(mux.linkState().up, false);
  assert.ok(mux.linkState().at instanceof Date);
});

test('a refusal reaches the opener as a refusal, and the link goes on', async () => {
  const { dialed, answered } = pair();
  const client = createMux(dialed, { side: 'dialed' });
  const server = createMux(answered, { side: 'answered' });
  const a2a = await client.open('a2a/1');
  (await within(server.accept())).close('refused');
  await assert.rejects(within(a2a.receive()), (error) => error instanceof StreamEnded && error.reason === 'refused');
  const acp = await client.open('acp/1');
  const other = await within(server.accept());
  await other.send('still here');
  assert.equal(text(await within(acp.receive())), 'still here');
});

/** A hostile peer, by frames, against a real mux. */
function against(limits = {}) {
  const sent = [];
  let listen;
  let onClose;
  const mux = createMux({
    send: async (message) => sent.push(decodeFrame(message)),
    onMessage: (handler) => {
      listen = handler;
    },
    onClose: (handler) => {
      onClose = handler;
    },
  }, { side: 'answered', limits });
  return { mux, sent, close: () => onClose(), frame: (frame) => listen(encodeFrame(frame)) };
}

test('a peer ignoring credit loses that stream and not the link', async () => {
  const { mux, sent, frame } = against({ window: 8 });
  frame({ kind: 'open', stream: 1, protocol: 'x' });
  frame({ kind: 'open', stream: 3, protocol: 'x' });
  frame({ kind: 'data', stream: 1, body: new Uint8Array(8) });
  frame({ kind: 'data', stream: 1, body: new Uint8Array(8) });
  frame({ kind: 'data', stream: 3, body: new Uint8Array(1) });
  const first = await mux.accept();
  const second = await mux.accept();
  await assert.rejects(first.receive(), (error) => error.reason === 'broken');
  assert.equal((await second.receive()).length, 1);
  assert.deepEqual(sent.find((item) => item.kind === 'close'), { kind: 'close', stream: 1, reason: 'broken', text: '' });
});

test('a message over the limit ends its stream', async () => {
  const { mux, frame } = against({ maxMessage: 8 });
  frame({ kind: 'open', stream: 1, protocol: 'x' });
  frame({ kind: 'data', stream: 1, body: new Uint8Array(9) });
  await assert.rejects((await mux.accept()).receive(), (error) => error.reason === 'broken');
});

test('opens past the limits are refused and held for nobody', async () => {
  const { mux, sent, frame } = against({ maxPendingOpens: 2 });
  for (const stream of [1, 3, 5]) frame({ kind: 'open', stream, protocol: 'x' });
  assert.deepEqual(sent, [{ kind: 'close', stream: 5, reason: 'refused', text: 'over a limit' }]);
  assert.ok(await mux.accept());
  assert.ok(await mux.accept());
});

test('a frame no peer may send ends the link', async () => {
  for (const frames of [[2], [1, 1], [3, 1]]) {
    const { mux, frame } = against();
    for (const stream of frames) frame({ kind: 'open', stream, protocol: 'x' });
    while ((await within(mux.accept())) !== null);
    await assert.rejects(mux.open('y'), (error) => error.reason === 'protocol');
  }
});

test('a closed link ends every stream, and data for an ended stream is ignored', async () => {
  const { mux, close, frame } = against();
  frame({ kind: 'open', stream: 1, protocol: 'x' });
  const stream = await mux.accept();
  frame({ kind: 'data', stream: 1, body: new Uint8Array(1) });
  close();
  assert.equal((await stream.receive()).length, 1, 'what arrived before is still read');
  assert.equal(await stream.receive(), null);
  assert.equal(await mux.accept(), null);
  frame({ kind: 'data', stream: 9, body: new Uint8Array(1) });
});
