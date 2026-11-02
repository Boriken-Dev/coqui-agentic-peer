/// Named channels inside a proven link, for Dart: the wire in `docs/link.md`, which `vectors/mux.json` holds as data. It is given a
/// link that already proved its peer, and adds no trust of its own. Nothing here replays: a stream delivers in order or fails with
/// why, and resuming is the host's, with its own cursor in the metadata of a new stream.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

const int _open = 0;
const int _data = 1;
const int _credit = 2;
const int _close = 3;
const int _ping = 4;
const int _pong = 5;
const int _more = 6;
const int _finish = 7;
const int _header = 5;
const int _maxProtocol = 64;
const int _maxReason = 256;

/// Why a stream was closed, on the wire. The order is the wire's.
enum CloseReason { done, refused, broken, superseded, revoked }

/// A protocol token: printable ASCII with no spaces, commas or equals signs, so it can go in a DNS-SD record as it is.
bool validProtocol(String protocol) {
  if (protocol.isEmpty || protocol.length > _maxProtocol) return false;
  return protocol.codeUnits.every(
    (unit) => unit > 0x20 && unit < 0x7f && unit != 0x2c && unit != 0x3d,
  );
}

/// Whether a link's first message opens a mux, rather than being plain ACP, whose JSON never starts with a zero byte.
bool startsMux(Uint8List first) => first.isNotEmpty && first[0] == _open;

sealed class Frame {
  const Frame(this.stream);
  final int stream;
  Uint8List get _body;
  int get _kind;

  Uint8List encode() {
    final body = _body;
    final out = Uint8List(_header + body.length);
    out[0] = _kind;
    ByteData.sublistView(out).setUint32(1, stream, Endian.little);
    out.setRange(_header, out.length, body);
    return out;
  }

  /// Reads a frame. Anything else is null, whoever sent it.
  static Frame? decode(Uint8List bytes) {
    if (bytes.length < _header) return null;
    final stream = ByteData.sublistView(bytes).getUint32(1, Endian.little);
    final body = Uint8List.sublistView(bytes, _header);
    switch (bytes[0]) {
      case _open:
        if (body.isEmpty || body.length < 1 + body[0]) return null;
        final protocol = _text(Uint8List.sublistView(body, 1, 1 + body[0]));
        if (protocol == null || !validProtocol(protocol)) return null;
        return OpenFrame(
          stream,
          protocol,
          Uint8List.fromList(Uint8List.sublistView(body, 1 + body[0])),
        );
      case _data:
        return body.isNotEmpty
            ? DataFrame(stream, Uint8List.fromList(body))
            : null;
      case _more:
        return body.isNotEmpty
            ? MoreFrame(stream, Uint8List.fromList(body))
            : null;
      case _credit:
        if (body.length != 4) return null;
        final credit = ByteData.sublistView(body).getUint32(0, Endian.little);
        return credit != 0 ? CreditFrame(stream, credit) : null;
      case _finish:
        return body.isEmpty ? FinishFrame(stream) : null;
      case _close:
        if (body.isEmpty ||
            body[0] >= CloseReason.values.length ||
            body.length > 1 + _maxReason) {
          return null;
        }
        final text = _text(Uint8List.sublistView(body, 1));
        return text == null
            ? null
            : CloseFrame(stream, CloseReason.values[body[0]], text);
      case _ping:
        return stream == 0 && body.isEmpty ? const PingFrame() : null;
      case _pong:
        return stream == 0 && body.isEmpty ? const PongFrame() : null;
      default:
        return null;
    }
  }
}

String? _text(Uint8List bytes) {
  try {
    return const Utf8Decoder().convert(bytes);
  } on FormatException {
    return null;
  }
}

final class OpenFrame extends Frame {
  OpenFrame(super.stream, this.protocol, [Uint8List? metadata])
    : metadata = metadata ?? Uint8List(0);
  final String protocol;
  final Uint8List metadata;
  @override
  int get _kind => _open;
  @override
  Uint8List get _body {
    final token = utf8.encode(protocol);
    return Uint8List.fromList([token.length, ...token, ...metadata]);
  }
}

final class DataFrame extends Frame {
  const DataFrame(super.stream, this.body);
  final Uint8List body;
  @override
  int get _kind => _data;
  @override
  Uint8List get _body => body;
}

final class MoreFrame extends Frame {
  const MoreFrame(super.stream, this.body);
  final Uint8List body;
  @override
  int get _kind => _more;
  @override
  Uint8List get _body => body;
}

final class CreditFrame extends Frame {
  const CreditFrame(super.stream, this.bytes);
  final int bytes;
  @override
  int get _kind => _credit;
  @override
  Uint8List get _body {
    final out = Uint8List(4);
    ByteData.sublistView(out).setUint32(0, bytes, Endian.little);
    return out;
  }
}

final class FinishFrame extends Frame {
  const FinishFrame(super.stream);
  @override
  int get _kind => _finish;
  @override
  Uint8List get _body => Uint8List(0);
}

final class CloseFrame extends Frame {
  const CloseFrame(super.stream, this.reason, [this.text = '']);
  final CloseReason reason;
  final String text;
  @override
  int get _kind => _close;
  @override
  Uint8List get _body =>
      Uint8List.fromList([reason.index, ...utf8.encode(text)]);
}

final class PingFrame extends Frame {
  const PingFrame() : super(0);
  @override
  int get _kind => _ping;
  @override
  Uint8List get _body => Uint8List(0);
}

final class PongFrame extends Frame {
  const PongFrame() : super(0);
  @override
  int get _kind => _pong;
  @override
  Uint8List get _body => Uint8List(0);
}

/// Which side of the link this is, so the two never pick the same stream id. Either side may open streams, whoever connected.
enum Side { dialed, answered }

/// Whether to notice a link that has gone silent. Silence on a stream never ends it.
final class Heartbeat {
  const Heartbeat(this.interval, this.misses);
  final Duration interval;
  final int misses;
}

/// What a mux will hold for its peer, which the peer cannot make it exceed. Every one is a setting.
final class MuxLimits {
  const MuxLimits({
    this.maxStreams = 32,
    this.maxPerProtocol = 16,
    this.window = 1024 * 1024,
    this.maxMessage = 16 * 1024 * 1024,
    this.maxFrame = 64 * 1024,
    this.maxMetadata = 4096,
    this.maxPendingOpens = 8,
    this.maxOpensPerMinute = 600,
    this.heartbeat,
  });
  final int maxStreams;
  final int maxPerProtocol;
  final int window;
  final int maxMessage;
  final int maxFrame;
  final int maxMetadata;
  final int maxPendingOpens;
  final int maxOpensPerMinute;
  final Heartbeat? heartbeat;
}

/// A stream ended other than in order, or was used after that.
final class StreamEnded implements Exception {
  const StreamEnded(this.reason, [this.text = '']);

  /// `refused`, `broken`, `superseded`, `revoked`, `done`, `protocol` when the peer broke the link as a whole, or `link-lost`.
  final String reason;
  final String text;
  @override
  String toString() =>
      'the stream ended: $reason${text.isEmpty ? '' : ': $text'}';
}

/// One stream inside a link.
final class MuxStream {
  MuxStream._(this._mux, this.id, this.protocol, this.metadata)
    : _creditLeft = _mux.limits.window;

  final Mux _mux;
  final int id;
  final String protocol;

  /// What the peer sent with it, opaque to the link: a token, a session key, a resume cursor.
  final Uint8List metadata;
  final Queue<Uint8List> _incoming = Queue();
  final BytesBuilder _partial = BytesBuilder(copy: false);
  int _held = 0;
  int _creditLeft;
  bool _finished = false;
  bool _peerFinished = false;
  String? _ended;
  String _endedText = '';
  bool _closed = false;
  Completer<void> _changed = Completer();

  void _wake() {
    final changed = _changed;
    _changed = Completer();
    changed.complete();
  }

  /// Sends one message, waiting for credit, so a slow reader is felt as a wait here and nowhere else.
  Future<void> send(Uint8List message) async {
    _check(message);
    for (;;) {
      _checkOpen();
      if (_creditLeft > 0) break;
      await _changed.future;
    }
    _creditLeft -= message.length;
    await _sendParts(message);
  }

  /// Sends now or says it cannot: false means full, for a host that would rather drop a slow reader than wait.
  bool trySend(Uint8List message) {
    _check(message);
    _checkOpen();
    if (_creditLeft <= 0) return false;
    _creditLeft -= message.length;
    unawaited(_sendParts(message).catchError((Object _) {}));
    return true;
  }

  void _check(Uint8List message) {
    if (message.isEmpty || message.length > _mux.limits.maxMessage) {
      throw ArgumentError.value(
        message.length,
        'message',
        'outside its bounds',
      );
    }
  }

  void _checkOpen() {
    final ended = _ended;
    if (ended != null) throw StreamEnded(ended, _endedText);
    if (_finished) throw StateError('this side said it was done');
  }

  /// In parts, so another stream's message can pass between them.
  Future<void> _sendParts(Uint8List message) async {
    final size = max(1, _mux.limits.maxFrame);
    var at = 0;
    while (message.length - at > size) {
      await _mux._send(
        MoreFrame(id, Uint8List.sublistView(message, at, at + size)),
      );
      at += size;
    }
    await _mux._send(DataFrame(id, Uint8List.sublistView(message, at)));
  }

  /// Says this side will send nothing more, and goes on reading. The peer's receive answers null after what was sent.
  Future<void> finish() async {
    _checkOpen();
    _finished = true;
    await _mux._send(FinishFrame(id));
  }

  /// Whether the peer said it was done sending with [finish]. [receive] answers null both for that and for a stream or link closed
  /// in order, and this tells them apart: false after a null means what the peer sent may be a part of what it meant to.
  bool get finishedByPeer => _peerFinished;

  /// The next message, or null when the stream ended in order. Throws [StreamEnded] otherwise.
  Future<Uint8List?> receive() async {
    for (;;) {
      if (_incoming.isNotEmpty) {
        final message = _incoming.removeFirst();
        _held -= message.length;
        // Reading frees room, so this is where credit goes back.
        unawaited(
          _mux._send(CreditFrame(id, message.length)).catchError((Object _) {}),
        );
        return message;
      }
      final ended = _ended;
      if (ended == 'done') return null;
      if (ended != null) throw StreamEnded(ended, _endedText);
      if (_peerFinished) return null;
      await _changed.future;
    }
  }

  /// Ends it from this side, saying why: refused, superseded or revoked, so the other side knows not to simply try again.
  void close([CloseReason reason = CloseReason.done, String text = '']) {
    if (_closed) return;
    _closed = true;
    final tell = _ended == null;
    _mux._streams.remove(id);
    _ended ??= 'done';
    _wake();
    if (tell) {
      unawaited(
        _mux
            ._send(CloseFrame(id, reason, _bounded(text)))
            .catchError((Object _) {}),
      );
    }
  }

  void _end(String why, [String text = '']) {
    if (_ended == null) {
      _ended = why;
      _endedText = text;
    }
    _wake();
  }
}

String _bounded(String text) {
  final bytes = utf8.encode(text);
  if (bytes.length <= _maxReason) return text;
  // Back to a character boundary, which a continuation byte is not.
  var end = _maxReason;
  while (end > 0 && (bytes[end] & 0xc0) == 0x80) {
    end -= 1;
  }
  return utf8.decode(bytes.sublist(0, end));
}

/// Channels inside one link. [incoming] carries whole messages from the link, and [send] sends one.
final class Mux {
  Mux({
    required Stream<Uint8List> incoming,
    required Future<void> Function(Uint8List) send,
    required Side side,
    this.limits = const MuxLimits(),
    Uint8List? first,
  }) : _sendRaw = send,
       _side = side,
       _nextStream = side == Side.dialed ? 1 : 2 {
    if (first != null) _take(first);
    _subscription = incoming.listen(
      _take,
      onDone: () => _lost('done'),
      onError: (Object _) => _lost('link-lost'),
    );
    final heartbeat = limits.heartbeat;
    if (heartbeat != null &&
        heartbeat.interval > Duration.zero &&
        heartbeat.misses > 0) {
      _lastHeard = DateTime.now();
      _beat = Timer.periodic(heartbeat.interval, (_) {
        if (DateTime.now().difference(_lastHeard) >=
            heartbeat.interval * heartbeat.misses) {
          _lost('link-lost');
        } else {
          unawaited(_send(const PingFrame()).catchError((Object _) {}));
        }
      });
    }
  }

  final MuxLimits limits;
  final Future<void> Function(Uint8List) _sendRaw;
  final Side _side;
  late final StreamSubscription<Uint8List> _subscription;
  final Map<int, MuxStream> _streams = {};
  final Queue<MuxStream> _pending = Queue();
  int _nextStream;
  int _peerStream = 0;
  int _opensThisMinute = 0;
  DateTime _minuteBegan = DateTime.now();
  DateTime _lastHeard = DateTime.now();
  Timer? _beat;
  String? _ended;
  DateTime? _endedAt;
  Completer<void> _accepting = Completer();
  Future<void> _opening = Future.value();

  /// Why the link ended, or null while it is up.
  String? get ended => _ended;

  /// When the link ended, for a host deciding what is lost.
  DateTime? get endedAt => _endedAt;

  Future<void> _send(Frame frame) {
    final ended = _ended;
    if (ended != null) return Future.error(StreamEnded(ended));
    return _sendRaw(frame.encode());
  }

  int _countOf(String protocol) =>
      _streams.values.where((stream) => stream.protocol == protocol).length;

  /// Opens a stream, with [metadata] for the side accepting it. The peer may still refuse it, which its first receive reports.
  Future<MuxStream> open(String protocol, [Uint8List? metadata]) async {
    final bytes = metadata ?? Uint8List(0);
    if (!validProtocol(protocol) || bytes.length > limits.maxMetadata) {
      throw ArgumentError.value(
        protocol,
        'protocol',
        'not a token, or too much metadata',
      );
    }
    final ended = _ended;
    if (ended != null) throw StreamEnded(ended);
    if (_streams.length >= limits.maxStreams ||
        _countOf(protocol) >= limits.maxPerProtocol) {
      throw StateError('too many streams');
    }
    final id = _nextStream;
    _nextStream += 2;
    final stream = MuxStream._(this, id, protocol, bytes);
    _streams[id] = stream;
    // One open at a time, in id order: the link may take a send a while, and a lower id after a higher one ends the peer's link.
    final turn = _opening.then((_) => _send(OpenFrame(id, protocol, bytes)));
    _opening = turn.catchError((Object _) {});
    try {
      await turn;
    } catch (_) {
      // The peer never heard of it, so it must not count against the limits here. Ids may skip.
      _streams.remove(id);
      rethrow;
    }
    return stream;
  }

  /// The next stream the peer opened, or null when the link has ended. It is the host's to serve or to refuse: a proof admits a
  /// peer to the link and grants it no protocol.
  Future<MuxStream?> accept() async {
    for (;;) {
      if (_pending.isNotEmpty) return _pending.removeFirst();
      if (_ended != null) return null;
      await _accepting.future;
    }
  }

  /// Stops reading the link. The link itself is the caller's to close.
  Future<void> close() async {
    await _subscription.cancel();
    _lost('done');
  }

  void _take(Uint8List message) {
    _lastHeard = DateTime.now();
    final frame = Frame.decode(message);
    final stream = frame == null ? null : _streams[frame.stream];
    switch (frame) {
      case null:
        _lost('protocol');
      case OpenFrame(
        stream: final id,
        protocol: final protocol,
        metadata: final metadata,
      ):
        _opened(id, protocol, metadata);
      case DataFrame(body: final body):
        if (stream != null) _part(stream, body, last: true);
      case MoreFrame(body: final body):
        if (stream != null) _part(stream, body, last: false);
      case CreditFrame(bytes: final bytes):
        if (stream != null) {
          stream._creditLeft = (stream._creditLeft + bytes).clamp(
            -1 << 40,
            0xffffffff,
          );
          stream._wake();
        }
      case FinishFrame():
        if (stream != null) {
          stream._peerFinished = true;
          stream._wake();
        }
      case CloseFrame(reason: final reason, text: final text):
        stream?._end(reason.name, text);
      case PingFrame():
        unawaited(_send(const PongFrame()).catchError((Object _) {}));
      case PongFrame():
        break;
    }
  }

  void _opened(int id, String protocol, Uint8List metadata) {
    final peerIsOdd = _side == Side.answered;
    // An id from the wrong side's range, or one already used, is a peer not speaking this at all.
    if (id.isOdd != peerIsOdd || id <= _peerStream) return _lost('protocol');
    _peerStream = id;
    if (DateTime.now().difference(_minuteBegan) >= const Duration(minutes: 1)) {
      _minuteBegan = DateTime.now();
      _opensThisMinute = 0;
    }
    _opensThisMinute += 1;
    if (_streams.length >= limits.maxStreams ||
        _countOf(protocol) >= limits.maxPerProtocol ||
        _pending.length >= limits.maxPendingOpens ||
        _opensThisMinute > limits.maxOpensPerMinute ||
        metadata.length > limits.maxMetadata) {
      unawaited(
        _send(
          CloseFrame(id, CloseReason.refused, 'over a limit'),
        ).catchError((Object _) {}),
      );
      return;
    }
    final stream = MuxStream._(this, id, protocol, metadata);
    _streams[id] = stream;
    _pending.add(stream);
    _wakeAccept();
  }

  void _part(MuxStream stream, Uint8List body, {required bool last}) {
    if (stream._ended != null) return;
    // A sender may start a message only while it has credit, so what is held before a new one is under the window.
    final starting = stream._partial.isEmpty;
    if (stream._partial.length + body.length > limits.maxMessage ||
        (starting && stream._held >= limits.window) ||
        stream._peerFinished) {
      stream._incoming.clear();
      stream._partial.clear();
      stream._held = 0;
      stream._end('broken');
      unawaited(
        _send(
          CloseFrame(stream.id, CloseReason.broken),
        ).catchError((Object _) {}),
      );
      return;
    }
    stream._held += body.length;
    stream._partial.add(body);
    if (!last) return;
    stream._incoming.add(stream._partial.takeBytes());
    stream._wake();
  }

  void _lost(String why) {
    if (_ended != null) return;
    _ended = why;
    _endedAt = DateTime.now();
    _beat?.cancel();
    for (final stream in _streams.values) {
      stream._end(why);
    }
    _wakeAccept();
  }

  void _wakeAccept() {
    final accepting = _accepting;
    _accepting = Completer();
    accepting.complete();
  }
}
