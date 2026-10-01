// Smoke test del confine FFI reale: carica la DLL compilata e percorre
// l'intero flusso (identità → carte → sessione → messaggio emoji → gruppo).
// Esegui con: flutter test
import 'dart:io';

import 'package:alienmsg/api.dart';
import 'package:alienmsg/ffi.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final dllPath =
      '${Directory.current.parent.path}\\target\\release\\alien_ffi.dll';

  setUpAll(() async {
    expect(File(dllPath).existsSync(), isTrue,
        reason: 'compila prima: cargo build --release -p alien-ffi');
    await AlienFfi.init(libraryPath: dllPath);
  });

  test('mnemonic → identity', () async {
    final m = await AlienApi.generateMnemonic();
    expect(m.split(' ').length, 24);
    expect(AlienApi.validateMnemonic(m), isTrue);
    final id = AlienApi.identityCreate(m);
    expect(id['pub_id'], isA<String>());
  });

  test('pairing + encrypt/decrypt + group via FFI', () async {
    final mA = await AlienApi.generateMnemonic();
    final mB = await AlienApi.generateMnemonic();
    final idA = AlienApi.identityCreate(mA);
    final idB = AlienApi.identityCreate(mB);
    final seedA = idA['identity'] as String;
    final seedB = idB['identity'] as String;

    final cardA = AlienApi.cardCreate(seedA);
    final cardB = AlienApi.cardCreate(seedB);

    // Alice pairs with Bob's card
    final s = AlienApi.sessionStart(
        seedA, cardA['card'] as String, cardB['card'] as String);
    var sessionA = s['session'] as String;

    // Alice encrypts (PairInit) and renders as emoji
    final e = AlienApi.encrypt(sessionA, 'ciao bob 👋');
    sessionA = e['session'] as String;
    final emojiText =
        AlienApi.render(e['envelope'] as String, 'emoji');
    expect(emojiText.startsWith('👽'), isTrue);

    // Bob decodes and accepts the session
    final envB64 = AlienApi.unrender(emojiText);
    final d = AlienApi.decrypt(
      identityB64: seedB,
      bundlesB64: [cardB['bundle'] as String],
      sessionsB64: const [],
      groupsB64: const [],
      envelopeB64: envB64,
    );
    expect(d['kind'], 'new_session');
    expect(d['plaintext'], 'ciao bob 👋');
    var sessionB = d['session'] as String;

    // Bob replies
    final e2 = AlienApi.encrypt(sessionB, 'ciao alice');
    sessionB = e2['session'] as String;
    final d2 = AlienApi.decrypt(
      identityB64: seedA,
      bundlesB64: [cardA['bundle'] as String],
      sessionsB64: [sessionA],
      groupsB64: const [],
      envelopeB64: e2['envelope'] as String,
    );
    expect(d2['kind'], 'pair');
    expect(d2['plaintext'], 'ciao alice');

    // Group: admin Alice, member Bob
    final gc = AlienApi.groupCreate(
      identityB64: seedA,
      sessionsB64: (d2['sessions'] as List).cast<String>(),
      memberIdsHex: [idB['pub_id'] as String],
      name: 'nucleo',
    );
    var groupA = gc['group'] as String;
    final dj = AlienApi.decrypt(
      identityB64: seedB,
      bundlesB64: [cardB['bundle'] as String],
      sessionsB64: [sessionB],
      groupsB64: const [],
      envelopeB64: gc['envelope'] as String,
    );
    expect(dj['kind'], 'group_joined');
    var groupB = dj['group'] as String;

    final ge = AlienApi.groupEncrypt(seedB, groupB, 'messaggio di gruppo');
    groupB = ge['group'] as String;
    final dg = AlienApi.decrypt(
      identityB64: seedA,
      bundlesB64: [cardA['bundle'] as String],
      sessionsB64: (gc['sessions'] as List).cast<String>(),
      groupsB64: [groupA],
      envelopeB64: ge['envelope'] as String,
    );
    expect(dg['kind'], 'group_text');
    expect(dg['plaintext'], 'messaggio di gruppo');
    groupA = (dg['groups'] as List).first as String;
    expect(AlienApi.groupInfo(groupA)['epoch'], 1);
  });

  test('vault password protection', () async {
    final dir = await Directory.systemTemp.createTemp('alienmsg-vault');
    final path = '${dir.path}${Platform.pathSeparator}test.vault';
    try {
      expect(AlienApi.vaultProbe(path)['exists'], isFalse);

      // create a protected vault
      var r = AlienApi.vaultOpen(path, 'segreta');
      var h = r['handle'] as int;
      expect(r['protected'], isTrue);
      AlienApi.vaultSet(h, 'k', 'dmFsdWU='); // b64('value')
      AlienApi.vaultSave(h, path);
      AlienApi.vaultClose(h);

      // probe flags it; empty and wrong passwords are rejected
      expect(AlienApi.vaultProbe(path)['needs_password'], isTrue);
      expect(() => AlienApi.vaultOpen(path, ''),
          throwsA(isA<AlienException>()));
      expect(() => AlienApi.vaultOpen(path, 'sbagliata'),
          throwsA(isA<AlienException>()));

      // correct password opens and reads
      r = AlienApi.vaultOpen(path, 'segreta');
      h = r['handle'] as int;
      expect(AlienApi.vaultGet(h, 'k'), 'dmFsdWU=');

      // removing the password downgrades to a plain vault
      AlienApi.vaultSetPassword(h, path, '');
      AlienApi.vaultClose(h);
      expect(AlienApi.vaultProbe(path)['needs_password'], isFalse);
      r = AlienApi.vaultOpen(path, '');
      h = r['handle'] as int;
      expect(AlienApi.vaultGet(h, 'k'), 'dmFsdWU=');
      AlienApi.vaultClose(h);
    } finally {
      await dir.delete(recursive: true);
    }
  });
}
