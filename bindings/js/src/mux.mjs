// Named channels inside one link, for a browser or Node: the wire in docs/link.md, which vectors/mux.json holds as data. It is
// given a link that already proved its peer, and adds no trust of its own.
const OPEN = 0;
const DATA = 1;
const CREDIT = 2;
const CLOSE = 3;
const PING = 4;
const PONG = 5;
const MORE = 6;
const FINISH = 7;
const HEADER = 5;
const REASONS = ['done', 'refused', 'broken', 'superseded', 'revoked'];
const MAX_PROTOCOL = 64;
const MAX_REASON = 256;

export const DEFAULT_LIMITS = Object.freeze({
  maxStreams: 32,
  maxPerProtocol: 16,
  window: 1024 * 1024,
  maxMessage: 16 * 1024 * 1024,
  maxFrame: 64 * 1024,
  maxMetadata: 4096,
  maxPendingOpens: 8,
  maxOpensPerMinute: 600,
});

/** A protocol token: printable ASCII with no spaces, commas or equals signs, so it can go in a DNS-SD record as it is. */
export function validProtocol(protocol) {
  return typeof protocol === 'string' && protocol.length > 0 && protocol.length <= MAX_PROTOCOL
    && /^[\x21-\x7e]+$/.test(protocol) && !/[,=]/.test(protocol);
}

/** Whether a link's first message opens a mux, rather than being plain ACP, whose JSON never starts with a zero byte. */
export function startsMux(first) {
  return first.length > 0 && first[0] === OPEN;
}

export function encodeFrame(frame) {
  let kind;
  let body;
  if (frame.kind === 'open') {
    kind = OPEN;
    const token = new TextEncoder().encode(frame.protocol);
    const metadata = frame.metadata ?? new Uint8Array();
    body = new Uint8Array(1 + token.length + metadata.length);
    body[0] = token.length;
    body.set(token, 1);
    body.set(metadata, 1 + token.length);
  } else if (frame.kind === 'data' || frame.kind === 'more') {
    kind = frame.kind === 'data' ? DATA : MORE;
    body = frame.body;
  } else if (frame.kind === 'finish') {
    kind = FINISH;
    body = new Uint8Array();
  } else if (frame.kind === 'credit') {
    kind = CREDIT;
    body = new Uint8Array(4);
    new DataView(body.buffer).setUint32(0, frame.bytes, true);
  } else if (frame.kind === 'close') {
    kind = CLOSE;
    const text = new TextEncoder().encode(frame.text ?? '');
    body = new Uint8Array(1 + text.length);
    body[0] = REASONS.indexOf(frame.reason);
    body.set(text, 1);
  } else {
    kind = frame.kind === 'ping' ? PING : PONG;
    body = new Uint8Array();
  }
  const out = new Uint8Array(HEADER + body.length);
  out[0] = kind;
  new DataView(out.buffer).setUint32(1, frame.stream, true);
  out.set(body, HEADER);
  return out;
}

function strictText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Reads a frame. Anything else is null, whoever sent it. */
export function decodeFrame(bytes) {
  if (bytes.length < HEADER) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stream = view.getUint32(1, true);
  const body = bytes.subarray(HEADER);
  switch (bytes[0]) {
    case OPEN: {
      if (body.length < 1 || body.length < 1 + body[0]) return null;
      const protocol = strictText(body.subarray(1, 1 + body[0]));
      if (protocol === null || !validProtocol(protocol)) return null;
      return { kind: 'open', stream, protocol, metadata: body.slice(1 + body[0]) };
    }
    case DATA:
      return body.length > 0 ? { kind: 'data', stream, body: body.slice() } : null;
    case MORE:
      return body.length > 0 ? { kind: 'more', stream, body: body.slice() } : null;
    case FINISH:
      return body.length === 0 ? { kind: 'finish', stream } : null;
    case CREDIT: {
      if (body.length !== 4) return null;
      const credit = view.getUint32(HEADER, true);
      return credit !== 0 ? { kind: 'credit', stream, bytes: credit } : null;
    }
    case CLOSE: {
      if (body.length < 1 || body[0] >= REASONS.length || body.length > 1 + MAX_REASON) return null;
      const text = strictText(body.subarray(1));
      return text === null ? null : { kind: 'close', stream, reason: REASONS[body[0]], text };
    }
    case PING:
      return stream === 0 && body.length === 0 ? { kind: 'ping' } : null;
    case PONG:
      return stream === 0 && body.length === 0 ? { kind: 'pong' } : null;
    default:
      return null;
  }
}

class Waiters {
  list = [];
  wait() {
    return new Promise((resolve) => this.list.push(resolve));
  }
  wake() {
    for (const resolve of this.list.splice(0)) resolve();
  }
}

function boundedText(text) {
  let bytes = new TextEncoder().encode(text);
  if (bytes.length <= MAX_REASON) return text;
  bytes = bytes.subarray(0, MAX_REASON);
  // Back to a character boundary, which a continuation byte is not.
  let end = bytes.length;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

class Stream {
  incoming = [];
  partial = [];
  partialSize = 0;
  held = 0;
  finished = false;
  peerFinished = false;
  ended = null;
  endedText = '';
  closed = false;
  changed = new Waiters();

  constructor(mux, id, protocol, metadata = new Uint8Array()) {
    this.mux = mux;
    this.id = id;
    this.protocol = protocol;
    this.metadata = metadata;
    this.credit = mux.limits.window;
  }

  /** Sends now or says it cannot: false means full, for a host that would rather drop a slow reader than wait. */
  trySend(message) {
    const body = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    if (body.length === 0 || body.length > this.mux.limits.maxMessage) throw new RangeError('a message outside its bounds');
    if (this.ended !== null) throw new StreamEnded(this.ended, this.endedText);
    if (this.finished) throw new RangeError('this side said it was done');
    if (this.credit <= 0) return false;
    this.credit -= body.length;
    this.sendParts(body).catch(() => {});
    return true;
  }

  /** In parts, so another stream's message can pass between them. */
  async sendParts(body) {
    const size = Math.max(1, this.mux.limits.maxFrame);
    for (let at = 0; at + size < body.length; at += size) {
      await this.mux.send({ kind: 'more', stream: this.id, body: body.subarray(at, at + size) });
    }
    const last = Math.floor((body.length - 1) / size) * size;
    await this.mux.send({ kind: 'data', stream: this.id, body: body.subarray(last) });
  }

  /** Says this side will send nothing more, and goes on reading. The peer's receive answers null after what was sent. */
  async finish() {
    if (this.ended !== null) throw new StreamEnded(this.ended, this.endedText);
    this.finished = true;
    await this.mux.send({ kind: 'finish', stream: this.id });
  }

  /** Sends one message, waiting for credit, so a slow reader is felt as a wait here and nowhere else. */
  async send(message) {
    const body = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    if (body.length === 0 || body.length > this.mux.limits.maxMessage) throw new RangeError('a message outside its bounds');
    for (;;) {
      if (this.ended !== null) throw new StreamEnded(this.ended, this.endedText);
      if (this.finished) throw new RangeError('this side said it was done');
      if (this.credit > 0) break;
      await this.changed.wait();
    }
    this.credit -= body.length;
    await this.sendParts(body);
  }

  /**
   * Whether the peer said it was done sending with finish. receive answers null both for that and for a stream or link closed in
   * order, and this tells them apart: false after a null means what the peer sent may be a part of what it meant to.
   */
  get finishedByPeer() {
    return this.peerFinished;
  }

  /** The next message, or null when the stream ended in order. Throws StreamEnded otherwise. */
  async receive() {
    for (;;) {
      if (this.incoming.length > 0) {
        const message = this.incoming.shift();
        this.held -= message.length;
        // Reading frees room, so this is where credit goes back.
        this.mux.send({ kind: 'credit', stream: this.id, bytes: message.length }).catch(() => {});
        return message;
      }
      if (this.ended === 'done') return null;
      if (this.ended !== null) throw new StreamEnded(this.ended, this.endedText);
      if (this.peerFinished) return null;
      await this.changed.wait();
    }
  }

  /** Ends it from this side, saying why: 'refused', 'superseded' or 'revoked', so the other side knows not to simply try again. */
  close(reason = 'done', text = '') {
    if (this.closed) return;
    this.closed = true;
    const tell = this.ended === null;
    this.mux.streams.delete(this.id);
    if (this.ended === null) this.ended = 'done';
    this.changed.wake();
    if (tell) this.mux.send({ kind: 'close', stream: this.id, reason, text: boundedText(text) }).catch(() => {});
  }

  end(why, text = '') {
    if (this.ended === null) {
      this.ended = why;
      this.endedText = text;
    }
    this.changed.wake();
  }
}

export class StreamEnded extends Error {
  constructor(reason, text = '') {
    super(`the stream ended: ${reason}${text ? `: ${text}` : ''}`);
    this.name = 'StreamEnded';
    this.reason = reason;
    this.text = text;
  }
}

class Mux {
  streams = new Map();
  pending = [];
  peerStream = 0;
  ended = null;
  opensThisMinute = 0;
  minuteBegan = Date.now();
  accepting = new Waiters();
  opening = Promise.resolve();

  constructor(link, side, limits) {
    this.link = link;
    this.side = side;
    this.limits = limits;
    this.nextStream = side === 'dialed' ? 1 : 2;
    this.peerIsOdd = side === 'answered';
  }

  send(frame) {
    if (this.ended !== null) return Promise.reject(new StreamEnded(this.ended));
    return Promise.resolve(this.link.send(encodeFrame(frame)));
  }

  countOf(protocol) {
    let count = 0;
    for (const stream of this.streams.values()) if (stream.protocol === protocol) count += 1;
    return count;
  }

  /** Opens a stream, with metadata for the side accepting it. The peer may still refuse it, which its first receive reports. */
  async open(protocol, metadata = new Uint8Array()) {
    if (!validProtocol(protocol) || metadata.length > this.limits.maxMetadata) throw new TypeError('not a protocol token, or too much metadata');
    if (this.ended !== null) throw new StreamEnded(this.ended);
    if (this.streams.size >= this.limits.maxStreams || this.countOf(protocol) >= this.limits.maxPerProtocol) throw new RangeError('too many streams');
    const id = this.nextStream;
    this.nextStream += 2;
    const stream = new Stream(this, id, protocol);
    this.streams.set(id, stream);
    // One open at a time, in id order: the link may take a send a while, and a lower id after a higher one ends the peer's link.
    const turn = this.opening.then(() => this.send({ kind: 'open', stream: id, protocol, metadata }));
    this.opening = turn.catch(() => {});
    try {
      await turn;
    } catch (error) {
      // The peer never heard of it, so it must not count against the limits here. Ids may skip.
      this.streams.delete(id);
      throw error;
    }
    return stream;
  }

  /** The next stream the peer opened, with its `protocol`, or null when the link has ended. */
  async accept() {
    for (;;) {
      if (this.pending.length > 0) return this.pending.shift();
      if (this.ended !== null) return null;
      await this.accepting.wait();
    }
  }

  /** One message from the link. What one stream does wrong ends that stream; what no peer may send ends the link. */
  take(message) {
    this.lastHeard = Date.now();
    const frame = decodeFrame(message);
    if (frame === null) return this.lost('protocol');
    if (frame.kind === 'ping') {
      this.send({ kind: 'pong' }).catch(() => {});
      return undefined;
    }
    if (frame.kind === 'pong') return undefined;
    const stream = this.streams.get(frame.stream);
    if (frame.kind === 'open') {
      if ((frame.stream % 2 === 1) !== this.peerIsOdd || frame.stream <= this.peerStream) return this.lost('protocol');
      this.peerStream = frame.stream;
      if (Date.now() - this.minuteBegan >= 60_000) {
        this.minuteBegan = Date.now();
        this.opensThisMinute = 0;
      }
      this.opensThisMinute += 1;
      if (this.streams.size >= this.limits.maxStreams || this.countOf(frame.protocol) >= this.limits.maxPerProtocol
        || this.pending.length >= this.limits.maxPendingOpens || this.opensThisMinute > this.limits.maxOpensPerMinute
        || frame.metadata.length > this.limits.maxMetadata) {
        this.send({ kind: 'close', stream: frame.stream, reason: 'refused', text: 'over a limit' }).catch(() => {});
        return undefined;
      }
      const opened = new Stream(this, frame.stream, frame.protocol, frame.metadata);
      this.streams.set(frame.stream, opened);
      this.pending.push(opened);
      this.accepting.wake();
    } else if (stream !== undefined) {
      if (frame.kind === 'data' || frame.kind === 'more') this.part(stream, frame.body, frame.kind === 'data');
      else if (frame.kind === 'finish') {
        stream.peerFinished = true;
        stream.changed.wake();
      } else if (frame.kind === 'credit') {
        stream.credit = Math.min(stream.credit + frame.bytes, 0xffffffff);
        stream.changed.wake();
      } else stream.end(frame.reason, frame.text);
    }
    return undefined;
  }

  part(stream, body, last) {
    if (stream.ended !== null) return;
    // A sender may start a message only while it has credit, so what is held before a new one is under the window.
    const starting = stream.partialSize === 0;
    if (stream.partialSize + body.length > this.limits.maxMessage || (starting && stream.held >= this.limits.window) || stream.peerFinished) {
      stream.incoming.length = 0;
      stream.partial = [];
      stream.partialSize = 0;
      stream.held = 0;
      stream.end('broken');
      this.send({ kind: 'close', stream: stream.id, reason: 'broken', text: '' }).catch(() => {});
      return;
    }
    stream.held += body.length;
    if (!last || !starting) {
      stream.partial.push(body);
      stream.partialSize += body.length;
    }
    if (!last) return;
    if (starting) {
      stream.incoming.push(body);
    } else {
      const whole = new Uint8Array(stream.partialSize);
      let at = 0;
      for (const piece of stream.partial) {
        whole.set(piece, at);
        at += piece.length;
      }
      stream.partial = [];
      stream.partialSize = 0;
      stream.incoming.push(whole);
    }
    stream.changed.wake();
  }

  lost(why) {
    if (this.ended !== null) return;
    this.ended = why;
    this.endedAt = new Date();
    clearInterval(this.beat);
    for (const stream of this.streams.values()) stream.end(why);
    this.accepting.wake();
  }

  /** Asks, and notices silence. Only a link with nothing heard at all is lost: a stream silent for hours is fine. */
  startHeartbeat({ interval, misses }) {
    if (!(interval > 0) || !(misses > 0)) return;
    this.lastHeard = Date.now();
    this.beat = setInterval(() => {
      if (Date.now() - this.lastHeard >= interval * misses) this.lost('link-lost');
      else this.send({ kind: 'ping' }).catch(() => {});
    }, interval);
    this.beat.unref?.();
  }
}

/**
 * A mux over a link that carries whole binary messages: `send(Uint8Array)`, and `onMessage(fn)` and `onClose(fn)`, each called
 * once to register. `side` is 'dialed' for the side that connected and 'answered' for the other; either may open streams. `limits`
 * may set `heartbeat: { interval, misses }` in milliseconds, off unless set. Returns `open`, `accept`, `linkState`.
 */
export function createMux(link, { side, limits = {}, first } = {}) {
  if (side !== 'dialed' && side !== 'answered') throw new TypeError('side is dialed or answered');
  const mux = new Mux(link, side, { ...DEFAULT_LIMITS, ...limits });
  link.onMessage((message) => mux.take(message));
  link.onClose(() => mux.lost('done'));
  if (first !== undefined) mux.take(first);
  if (mux.limits.heartbeat) mux.startHeartbeat(mux.limits.heartbeat);
  return {
    open: (protocol, metadata) => mux.open(protocol, metadata),
    accept: () => mux.accept(),
    linkState: () => (mux.ended === null ? { up: true } : { up: false, why: mux.ended, at: mux.endedAt }),
  };
}
