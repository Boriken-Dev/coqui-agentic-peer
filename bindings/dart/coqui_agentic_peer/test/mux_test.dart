@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:coqui_agentic_peer/coqui_agentic_peer.dart';
import 'package:test/test.dart';

Uint8List _unhex(String text) => Uint8List.fromList([
  for (var at = 0; at < text.length; at += 2)
    int.parse(text.substring(at, at + 2), radix: 16),
]);

Uint8List _bytes(String text) => Uint8List.fromList(utf8.encode(text));

const _wait = Duration(seconds: 2);

/// Two ends in memory.
(Mux, Mux) _pair({MuxLimits limits = const MuxLimits()}) {
  final toA = StreamController<Uint8List>();
  final toB = StreamController<Uint8List>();
  final a = Mux(
    incoming: toA.stream,
    send: (message) async => toB.add(message),
    side: Side.dialed,
    limits: limits,
  );
  final b = Mux(
    incoming: toB.stream,
    send: (message) async => toA.add(message),
    side: Side.answered,
    limits: limits,
  );
  return (a, b);
}

/// A hostile peer, by frames, against a real mux.
final class _Against {
  _Against({MuxLimits limits = const MuxLimits()}) {
    mux = Mux(
      incoming: _in.stream,
      send: (message) async => sent.add(Frame.decode(message)!),
      side: Side.answered,
      limits: limits,
    );
  }
  final _in = StreamController<Uint8List>();
  final List<Frame> sent = [];
  late final Mux mux;
  void frame(Frame frame) => _in.add(frame.encode());
}

void main() {
  test('the vectors are the wire', () {
    final vectors =
        jsonDecode(File('../../../vectors/mux.json').readAsStringSync())
            as Map<String, dynamic>;
    for (final vector
        in (vectors['frames'] as List).cast<Map<String, dynamic>>()) {
      final bytes = _unhex(vector['hex'] as String);
      final frame = Frame.decode(bytes);
      expect(frame, isNotNull, reason: vector['name'] as String);
      expect(frame!.stream, vector['stream'] ?? 0);
      switch (vector['kind']) {
        case 'open':
          expect((frame as OpenFrame).protocol, vector['protocol']);
          expect(frame.metadata, _unhex(vector['metadata'] as String? ?? ''));
        case 'more':
          expect((frame as MoreFrame).body, _unhex(vector['body'] as String));
        case 'data':
          expect((frame as DataFrame).body, _unhex(vector['body'] as String));
        case 'credit':
          expect((frame as CreditFrame).bytes, vector['bytes']);
        case 'close':
          expect((frame as CloseFrame).reason.name, vector['reason']);
          expect(frame.text, vector['text'] as String? ?? '');
      }
      expect(frame.encode(), bytes, reason: vector['name'] as String);
    }
    for (final vector
        in (vectors['invalid'] as List).cast<Map<String, dynamic>>()) {
      expect(
        Frame.decode(_unhex(vector['hex'] as String)),
        isNull,
        reason: vector['name'] as String,
      );
    }
  });

  test(
    'the decoder takes any bytes without throwing, and what it takes encodes back to them',
    () {
      final random = Random(12345);
      for (var round = 0; round < 20000; round++) {
        final bytes = Uint8List.fromList(
          List.generate(
            random.nextInt(16),
            (_) => round.isEven ? random.nextInt(5) : random.nextInt(256),
          ),
        );
        final frame = Frame.decode(bytes);
        if (frame != null) expect(frame.encode(), bytes);
      }
    },
  );

  test('a first message opening a mux is told from plain ACP', () {
    expect(startsMux(OpenFrame(1, 'acp/1').encode()), isTrue);
    expect(startsMux(_bytes('{"jsonrpc":"2.0"}')), isFalse);
    expect(startsMux(Uint8List(0)), isFalse);
  });

  test('a protocol token can go in a record as it is', () {
    for (final good in [
      'acp/1',
      'a2a/1',
      'mcp',
      'tcp/1',
      'dev.boriken.ai6/tether',
    ]) {
      expect(validProtocol(good), isTrue, reason: good);
    }
    for (final bad in ['', 'a b', 'a,b', 'a=b', 'é', 'x' * 65]) {
      expect(validProtocol(bad), isFalse, reason: bad);
    }
  });

  test('two protocols run at once, each on its own stream', () async {
    final (client, server) = _pair();
    final acp = await client.open('acp/1');
    final mcp = await client.open('mcp');
    await acp.send(_bytes('to acp'));
    await mcp.send(_bytes('to mcp'));
    final first = (await server.accept().timeout(_wait))!;
    final second = (await server.accept().timeout(_wait))!;
    expect([first.protocol, second.protocol], ['acp/1', 'mcp']);
    expect(utf8.decode((await first.receive().timeout(_wait))!), 'to acp');
    expect(utf8.decode((await second.receive().timeout(_wait))!), 'to mcp');
    await first.send(_bytes('acp says'));
    expect(utf8.decode((await acp.receive().timeout(_wait))!), 'acp says');
  });

  test(
    'metadata reaches the side accepting, and each cause arrives as itself',
    () async {
      for (final reason in [
        CloseReason.refused,
        CloseReason.superseded,
        CloseReason.revoked,
      ]) {
        final (client, server) = _pair();
        final stream = await client.open('x', Uint8List.fromList([42]));
        final incoming = (await server.accept().timeout(_wait))!;
        expect(incoming.metadata, [42]);
        incoming.close(reason, 'because');
        await expectLater(
          stream.receive().timeout(_wait),
          throwsA(
            isA<StreamEnded>()
                .having((ended) => ended.reason, 'reason', reason.name)
                .having((ended) => ended.text, 'text', 'because'),
          ),
        );
      }
    },
  );

  test('either side opens streams, whoever connected', () async {
    final (client, server) = _pair();
    final stream = await server.open('dev.boriken.ai6/tether');
    await stream.send(_bytes('from the side that answered'));
    final incoming = (await client.accept().timeout(_wait))!;
    expect(incoming.protocol, 'dev.boriken.ai6/tether');
    expect(
      utf8.decode((await incoming.receive().timeout(_wait))!),
      'from the side that answered',
    );
  });

  test(
    'finishing ends one direction, and the answer still comes back',
    () async {
      final (client, server) = _pair();
      final stream = await client.open('a2a/1');
      await stream.send(_bytes('request'));
      await stream.finish();
      await expectLater(stream.send(_bytes('more')), throwsStateError);
      final incoming = (await server.accept().timeout(_wait))!;
      expect(
        utf8.decode((await incoming.receive().timeout(_wait))!),
        'request',
      );
      expect(
        await incoming.receive().timeout(_wait),
        isNull,
        reason: 'finished, not truncated',
      );
      await incoming.send(_bytes('answer'));
      incoming.close();
      expect(utf8.decode((await stream.receive().timeout(_wait))!), 'answer');
      expect(await stream.receive().timeout(_wait), isNull);
    },
  );

  test('a long message arrives whole, cut into frames', () async {
    final (client, server) = _pair(limits: const MuxLimits(maxFrame: 1024));
    final stream = await client.open('long');
    await stream.send(Uint8List(4106)..fillRange(0, 4106, 9));
    final incoming = (await server.accept().timeout(_wait))!;
    final message = (await incoming.receive().timeout(_wait))!;
    expect(message.length, 4106);
    expect(message.every((byte) => byte == 9), isTrue);
  });

  test(
    'parts past the largest message end the stream, and data after finish breaks it',
    () async {
      final first = _Against(limits: const MuxLimits(maxMessage: 8));
      first
        ..frame(OpenFrame(1, 'x'))
        ..frame(MoreFrame(1, Uint8List(5)))
        ..frame(MoreFrame(1, Uint8List(5)));
      final over = (await first.mux.accept().timeout(_wait))!;
      await expectLater(
        over.receive().timeout(_wait),
        throwsA(isA<StreamEnded>()),
      );
      final second = _Against();
      second
        ..frame(OpenFrame(1, 'x'))
        ..frame(FinishFrame(1))
        ..frame(DataFrame(1, Uint8List(1)));
      await pumpEventQueue();
      final finished = (await second.mux.accept().timeout(_wait))!;
      await expectLater(
        finished.receive().timeout(_wait),
        throwsA(isA<StreamEnded>()),
      );
    },
  );

  test(
    'trySend says full at once, and a link answering pings is not lost for a silent stream',
    () async {
      final (client, server) = _pair(
        limits: const MuxLimits(
          window: 8,
          heartbeat: Heartbeat(Duration(milliseconds: 20), 3),
        ),
      );
      final stream = await client.open('quiet');
      await server.accept().timeout(_wait);
      expect(stream.trySend(Uint8List(8)), isTrue);
      expect(stream.trySend(Uint8List(1)), isFalse);
      await Future<void>.delayed(const Duration(milliseconds: 150));
      expect(client.ended, isNull);
    },
  );

  test('a link gone silent is lost, and every stream hears why', () async {
    final mux = Mux(
      incoming: const Stream<Uint8List>.empty(
        broadcast: true,
      ).asBroadcastStream().where((_) => false),
      send: (_) async {},
      side: Side.dialed,
    );
    await mux.close();
    final silent = StreamController<Uint8List>();
    final watched = Mux(
      incoming: silent.stream,
      send: (_) async {},
      side: Side.dialed,
      limits: const MuxLimits(
        heartbeat: Heartbeat(Duration(milliseconds: 10), 2),
      ),
    );
    final stream = await watched.open('x');
    await expectLater(
      stream.receive().timeout(_wait),
      throwsA(
        isA<StreamEnded>().having(
          (ended) => ended.reason,
          'reason',
          'link-lost',
        ),
      ),
    );
    expect(watched.ended, 'link-lost');
    expect(watched.endedAt, isNotNull);
  });

  test('a stream that stops reading holds up only itself', () async {
    final (client, server) = _pair(limits: const MuxLimits(window: 16));
    final stuck = await client.open('stuck');
    final live = await client.open('live');
    final serverStuck = (await server.accept().timeout(_wait))!;
    final serverLive = (await server.accept().timeout(_wait))!;
    await stuck.send(Uint8List(32));
    var released = false;
    final waiting = stuck.send(Uint8List(8)).then((_) => released = true);
    for (var round = 0; round < 50; round++) {
      await live.send(Uint8List(8)..fillRange(0, 8, round));
      expect((await serverLive.receive().timeout(_wait))![0], round);
    }
    expect(released, isFalse, reason: 'the stuck stream has no credit');
    await serverStuck.receive().timeout(_wait);
    await waiting.timeout(_wait);
    expect(released, isTrue, reason: 'reading gives credit back');
  });

  test(
    'a refusal reaches the opener as a refusal, and the link goes on',
    () async {
      final (client, server) = _pair();
      final a2a = await client.open('a2a/1');
      (await server.accept().timeout(_wait))!.close(CloseReason.refused);
      await expectLater(
        a2a.receive().timeout(_wait),
        throwsA(
          isA<StreamEnded>().having(
            (ended) => ended.reason,
            'reason',
            'refused',
          ),
        ),
      );
      final acp = await client.open('acp/1');
      final other = (await server.accept().timeout(_wait))!;
      await other.send(_bytes('still here'));
      expect(utf8.decode((await acp.receive().timeout(_wait))!), 'still here');
    },
  );

  test('a peer ignoring credit loses that stream and not the link', () async {
    final peer = _Against(limits: const MuxLimits(window: 8));
    peer
      ..frame(OpenFrame(1, 'x'))
      ..frame(OpenFrame(3, 'x'))
      ..frame(DataFrame(1, Uint8List(8)))
      ..frame(DataFrame(1, Uint8List(8)))
      ..frame(DataFrame(3, Uint8List(1)));
    // All of them in before anything reads, which would give credit back.
    await pumpEventQueue();
    final first = (await peer.mux.accept().timeout(_wait))!;
    final second = (await peer.mux.accept().timeout(_wait))!;
    await expectLater(
      first.receive().timeout(_wait),
      throwsA(
        isA<StreamEnded>().having((ended) => ended.reason, 'reason', 'broken'),
      ),
    );
    expect((await second.receive().timeout(_wait))!.length, 1);
    final told = peer.sent.whereType<CloseFrame>().single;
    expect([told.stream, told.reason], [1, CloseReason.broken]);
  });

  test('a message over the limit ends its stream', () async {
    final peer = _Against(limits: const MuxLimits(maxMessage: 8));
    peer
      ..frame(OpenFrame(1, 'x'))
      ..frame(DataFrame(1, Uint8List(9)));
    final stream = (await peer.mux.accept().timeout(_wait))!;
    await expectLater(
      stream.receive().timeout(_wait),
      throwsA(isA<StreamEnded>()),
    );
  });

  test('opens past the limits are refused and held for nobody', () async {
    final peer = _Against(limits: const MuxLimits(maxPendingOpens: 2));
    for (final id in [1, 3, 5]) {
      peer.frame(OpenFrame(id, 'x'));
    }
    await pumpEventQueue();
    final told = peer.sent.whereType<CloseFrame>().single;
    expect([told.stream, told.reason], [5, CloseReason.refused]);
    expect(await peer.mux.accept().timeout(_wait), isNotNull);
    expect(await peer.mux.accept().timeout(_wait), isNotNull);
  });

  test('a frame no peer may send ends the link', () async {
    for (final ids in [
      [2],
      [1, 1],
      [3, 1],
    ]) {
      final peer = _Against();
      for (final id in ids) {
        peer.frame(OpenFrame(id, 'x'));
      }
      while (await peer.mux.accept().timeout(_wait) != null) {}
      await expectLater(
        peer.mux.open('y'),
        throwsA(
          isA<StreamEnded>().having(
            (ended) => ended.reason,
            'reason',
            'protocol',
          ),
        ),
      );
    }
  });

  test(
    'a closed link ends every stream, with what arrived before still read',
    () async {
      final incoming = StreamController<Uint8List>();
      final mux = Mux(
        incoming: incoming.stream,
        send: (_) async {},
        side: Side.answered,
      );
      incoming
        ..add(OpenFrame(1, 'x').encode())
        ..add(DataFrame(1, Uint8List(1)).encode());
      final stream = (await mux.accept().timeout(_wait))!;
      await incoming.close();
      expect((await stream.receive().timeout(_wait))!.length, 1);
      expect(await stream.receive().timeout(_wait), isNull);
      expect(await mux.accept().timeout(_wait), isNull);
    },
  );
}
