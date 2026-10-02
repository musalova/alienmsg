import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'api.dart';
import 'plat.dart' as plat;

class Contact {
  String name;
  final String pubId; // hex owner id from their card
  String card; // b64 postcard ContactCard
  bool verified;
  String? session; // b64 SessionState blob
  String? sessionId; // hex
  Contact({
    required this.name,
    required this.pubId,
    required this.card,
    this.verified = false,
    this.session,
    this.sessionId,
  });

  Map<String, dynamic> toJson() => {
        'name': name,
        'pub_id': pubId,
        'card': card,
        'verified': verified,
        'session': session,
        'session_id': sessionId,
      };
  static Contact fromJson(Map<String, dynamic> j) => Contact(
        name: j['name'] ?? '',
        pubId: j['pub_id'] ?? '',
        card: j['card'] ?? '',
        verified: j['verified'] ?? false,
        session: j['session'],
        sessionId: j['session_id'],
      );
}

class GroupChat {
  String name;
  final String groupId; // hex
  String blob; // b64 GroupState
  GroupChat({required this.name, required this.groupId, required this.blob});

  Map<String, dynamic> toJson() =>
      {'name': name, 'group_id': groupId, 'blob': blob};
  static GroupChat fromJson(Map<String, dynamic> j) => GroupChat(
      name: j['name'] ?? '', groupId: j['group_id'] ?? '', blob: j['blob'] ?? '');
}

/// The vault file is password-protected; [Store.isLocked] is set and the UI
/// should ask for the password and retry [Store.open].
class VaultLockedException implements Exception {
  const VaultLockedException();
  @override
  String toString() => 'vault locked';
}

/// One persisted chat bubble: [mine] aligns right, [system] renders as a
/// centered notice, [from] shows a sender label on group messages.
class ChatEntry {
  final String text;
  final bool mine;
  final String? from;
  final bool system;
  const ChatEntry(this.text,
      {this.mine = false, this.from, this.system = false});

  Map<String, dynamic> toJson() =>
      {'t': text, 'mine': mine, 'from': from, 'sys': system};
  static ChatEntry fromJson(Map<String, dynamic> j) => ChatEntry(
        j['t'] as String? ?? '',
        mine: j['mine'] == true,
        from: j['from'] as String?,
        system: j['sys'] == true,
      );
}

/// Decrypted inbound item produced by [Store.processInbound].
class InboundResult {
  final String kind; // 'card' | 'text' | 'group_text' | 'group_joined' | 'rotated' | 'info'
  final String text;
  final String? peerId;
  final String? groupId;
  InboundResult(this.kind, this.text, {this.peerId, this.groupId});
}

class Store extends ChangeNotifier {
  int? _vault;
  String? _vaultPath;
  bool _locked = false;
  bool _gated = false; // app gate (PIN/Hello) — separate from vault lock
  bool vaultProtected = false;

  String? identitySeed; // b64 seed
  String? pubId; // hex
  String? recoveryPhrase; // 24 words, kept for optional backup
  List<String> bundles = []; // b64 CardBundles
  List<Contact> contacts = [];
  List<GroupChat> groups = [];

  /// The password that opened the vault (device-bound random key or the
  /// user's legacy password). Kept so [setPin] can re-wrap the device key
  /// without asking again.
  String? _devPass;

  /// App lock gate: null = open, 'pin' = PIN code, 'hello' = Windows Hello.
  /// 'pin' additionally wraps the device key cryptographically (see
  /// [unlockWithPin]) so the vault is unreadable without it.
  String? lockMode;

  /// True when the device key is PIN-wrapped: the vault cannot be opened
  /// until the user enters the PIN. [isLocked] stays false — this is a
  /// distinct pre-open state.
  bool needsPinToOpen = false;

  /// Set when a persist call failed (e.g. storage quota exhausted on web).
  /// Surfaced as a warning banner; retried on the next mutation.
  bool persistFailed = false;

  /// Dismiss the "storage full" banner (the next real write retries anyway).
  void acknowledgePersistFailure() {
    persistFailed = false;
    notifyListeners();
  }

  bool get isOpen => _vault != null;

  /// The vault exists and is bound to a password we haven't supplied yet.
  bool get isLocked => _locked;

  /// App-level gate (PIN / Windows Hello): vault is already open but the UI
  /// asks for authentication before showing anything.
  bool get isGated => _gated;
  void gate() {
    _gated = true;
    notifyListeners();
  }

  void ungate() {
    _gated = false;
    notifyListeners();
  }
  String? get vaultPath => _vaultPath;
  bool get hasIdentity => identitySeed != null;

  /// Record the vault path before it is opened — needed when a PIN-wrapped
  /// device key must be unwrapped (and the PIN verified) *before* [open].
  void prepareVaultPath(String path) => _vaultPath = path;

  static Future<String> defaultVaultPath() => plat.defaultVaultPath();

  /// Sidecar names next to the vault: the wrapped vault password
  /// (device binding), an optional wrapped PIN, and a Hello marker.
  static String devkeyPath(String vaultPath) => '$vaultPath.devkey';
  static String pinPath(String vaultPath) => '$vaultPath.pin';
  static String helloPath(String vaultPath) => '$vaultPath.hello';

  /// Read + unwrap the device-bound vault password. Returns null when no
  /// sidecar exists; throws when unwrap fails (vault copied to another
  /// device/account). Falls back to `devkey.tmp` — bindDevice writes it
  /// before rekeying, so it holds the *new* password if the app died between
  /// the vault save and the promote.
  static Future<String?> devicePassword(String vaultPath) async {
    final v = await plat.secureRead(vaultPath, 'devkey');
    if (v != null) return v;
    return plat.secureRead(vaultPath, 'devkey.tmp');
  }

  /// Marker prefix on the device key when it is PIN-wrapped: the stored
  /// value is `pin:<base64 ALNP blob>` and cannot be used until
  /// [unlockWithPin] unwraps it with the user's PIN.
  static const pinPrefix = 'pin:';

  /// True when the stored device key for [vaultPath] is PIN-wrapped.
  static Future<bool> devkeyNeedsPin(String vaultPath) async {
    final v = await devicePassword(vaultPath);
    return v != null && v.startsWith(pinPrefix);
  }

  /// Which lock gate is configured for [vaultPath]: 'pin' | 'hello' | null.
  static Future<String?> detectLockMode(String vaultPath) async {
    if (await devkeyNeedsPin(vaultPath)) return 'pin';
    if (await plat.secureRead(vaultPath, 'hello') != null) return 'hello';
    // Legacy marker from before PIN became a cryptographic wrap — the gate
    // still applies and gets migrated on the next successful unlock.
    if (await plat.secureRead(vaultPath, 'pin') != null) return 'pin';
    return null;
  }

  /// Open (or create) the vault at [path].
  ///
  /// Throws [VaultLockedException] when the file is password-protected and
  /// `password` is empty — the app should prompt and call [unlock]. Any other
  /// open failure is treated as corruption: the file is renamed aside (no data
  /// loss) and a fresh vault is created, so the app can never wedge at boot.
  /// Note a *wrong* password on a protected vault also throws
  /// [VaultLockedException] — the file is never renamed under it.
  Future<void> open(String path, String password) async {
    _vaultPath = path;
    try {
      final r = AlienApi.vaultOpen(path, password);
      _vault = r['handle'] as int;
      vaultProtected = r['protected'] == true;
    } catch (_) {
      final probe = AlienApi.vaultProbe(path);
      if (probe['needs_password'] == true) {
        // Password-bound vault: it is intact, just locked. Surface the lock
        // state and let the UI ask for the password — never quarantine it.
        _locked = true;
        notifyListeners();
        throw const VaultLockedException();
      }
      // Corrupt vault blob: move it aside (no data loss) and start fresh
      // instead of leaving the app permanently unable to boot.
      AlienApi.vaultRename(
          path, '$path.corrupt-${DateTime.now().millisecondsSinceEpoch}');
      final r = AlienApi.vaultOpen(path, password);
      _vault = r['handle'] as int;
      vaultProtected = r['protected'] == true;
    }
    _locked = false;
    _devPass = password;
    _load();
  }

  /// Retry [open] with the password typed on the lock screen.
  /// On success, migrates the vault to transparent device-bound unlock by
  /// writing the DPAPI sidecar (the vault keeps its existing password).
  Future<void> unlock(String password) async {
    await open(_vaultPath!, password);
    await _migrateDeviceKey(password);
  }

  /// Write the device-bound sidecar wrapping [password] if absent, so the
  /// vault auto-unlocks on this device next boot.
  Future<void> _migrateDeviceKey(String password) async {
    final path = _vaultPath;
    if (path == null) return;
    try {
      if (await devicePassword(path) != null) return;
    } catch (_) {}
    await plat.secureWrite(path, 'devkey', password);
  }

  /// Set or clear (empty string) the vault password. Persists immediately.
  /// Returns whether the vault is now password-protected.
  bool setVaultPassword(String password) {
    vaultProtected = AlienApi.vaultSetPassword(_vault!, _vaultPath!, password);
    _persist();
    notifyListeners();
    return vaultProtected;
  }

  /// PIN-first unlock: the device key was PIN-wrapped at [setPin] time, so
  /// the vault cannot open until this unwraps it. Wrong PIN = AEAD failure —
  /// verification is cryptographic, nothing plaintext is compared.
  Future<void> unlockWithPin(String pin) async {
    final path = _vaultPath;
    final wrapped = await devicePassword(path ?? '');
    if (path == null || wrapped == null || !wrapped.startsWith(pinPrefix)) {
      throw const VaultLockedException();
    }
    final devPass = AlienApi.pinUnwrap(pin, wrapped.substring(pinPrefix.length));
    await open(path, utf8.decode(base64Decode(devPass)));
    needsPinToOpen = false;
  }

  static T? _decodeVaultJson<T>(String? b64, T Function(dynamic json) f) {
    if (b64 == null) return null;
    try {
      return f(jsonDecode(utf8.decode(base64Decode(b64))));
    } catch (_) {
      return null; // corrupt entry: ignore instead of crashing startup
    }
  }

  void _load() {
    identitySeed = AlienApi.vaultGet(_vault!, 'identity');
    recoveryPhrase = _decodeVaultJson<String?>(
        AlienApi.vaultGet(_vault!, 'recovery'), (j) => j as String?);
    final meta = AlienApi.vaultGet(_vault!, 'meta');
    pubId = _decodeVaultJson<String?>(meta, (j) => j['pub_id'] as String?);
    final bundlesJson = AlienApi.vaultGet(_vault!, 'bundles');
    bundles = _decodeVaultJson(bundlesJson, (j) => (j as List).cast<String>()) ?? [];
    final contactsJson = AlienApi.vaultGet(_vault!, 'contacts');
    contacts = _decodeVaultJson(contactsJson,
            (j) => (j as List).map((e) => Contact.fromJson(e)).toList()) ??
        [];
    final groupsJson = AlienApi.vaultGet(_vault!, 'groups');
    groups = _decodeVaultJson(groupsJson,
            (j) => (j as List).map((e) => GroupChat.fromJson(e)).toList()) ??
        [];
    notifyListeners();
  }

  /// Prekey bundles accumulate one per generated card; cap so the vault
  /// can't grow without bound (oldest unclaimed cards become unusable).
  static const _bundleCap = 300;

  void _persist() {
    final v = _vault;
    if (v == null) return; // wiped/closed vault: nothing to persist to
    try {
      if (identitySeed != null) AlienApi.vaultSet(v, 'identity', identitySeed!);
      if (recoveryPhrase != null) {
        AlienApi.vaultSet(v, 'recovery',
            base64Encode(utf8.encode(jsonEncode(recoveryPhrase))));
      }
      AlienApi.vaultSet(v, 'meta',
          base64Encode(utf8.encode(jsonEncode({'pub_id': pubId}))));
      if (bundles.length > _bundleCap) {
        bundles.removeRange(0, bundles.length - _bundleCap);
      }
      AlienApi.vaultSet(
          v, 'bundles', base64Encode(utf8.encode(jsonEncode(bundles))));
      AlienApi.vaultSet(
          v,
          'contacts',
          base64Encode(
              utf8.encode(jsonEncode(contacts.map((c) => c.toJson()).toList()))));
      AlienApi.vaultSet(
          v,
          'groups',
          base64Encode(
              utf8.encode(jsonEncode(groups.map((g) => g.toJson()).toList()))));
      if (_vaultPath != null) AlienApi.vaultSave(v, _vaultPath!);
      if (persistFailed) {
        persistFailed = false;
        notifyListeners();
      }
    } catch (_) {
      // Storage quota exhausted (localStorage ~5MB) or a closed handle —
      // don't crash the caller, flag it so the UI can warn instead.
      if (!persistFailed) {
        persistFailed = true;
        notifyListeners();
      }
    }
  }

  void createIdentity(String mnemonic, String passphrase) {
    final r = AlienApi.identityCreate(mnemonic, passphrase);
    identitySeed = r['identity'] as String;
    pubId = r['pub_id'] as String;
    recoveryPhrase = mnemonic;
    _persist();
    notifyListeners();
  }

  /// Create an identity the user never has to back up: internally it is still
  /// a BIP-39 phrase (kept encrypted in the vault, shown only on request), but
  /// nothing is asked or displayed during onboarding.
  Future<void> createIdentitySimple() async {
    final m = await AlienApi.generateMnemonic();
    createIdentity(m, '');
  }

  /// Bind the vault to this device: replace the vault password with a random
  /// 256-bit key wrapped by the platform keystore (DPAPI on Windows, Keystore/
  /// Keychain on mobile) and stored in a sidecar. A copied vault file cannot
  /// be opened elsewhere.
  /// Ordered so a crash can never strand the vault: on Windows devkey.tmp
  /// (new pw) is written BEFORE the rekey and promoted after it; if the vault
  /// has no password yet, the empty-password devkey is written first as a
  /// fallback.
  Future<void> bindDevice() async {
    final path = _vaultPath;
    final v = _vault;
    if (path == null || v == null) return;
    try {
      if (await devicePassword(path) == null && !vaultProtected) {
        await plat.secureWrite(path, 'devkey', '');
      }
    } catch (_) {}
    final devPass = 'dev.${AlienApi.randomBytes(32)}';
    await plat.secureWrite(path, 'devkey.tmp', devPass);
    setVaultPassword(devPass); // rekeys + saves the vault
    await plat.secureWrite(path, 'devkey', devPass);
    await plat.secureDelete(path, 'devkey.tmp');
  }

  /// Enable/disable the PIN gate. Null disables.
  ///
  /// When set, the device key is rewritten PIN-wrapped (`pin:<blob>`): from
  /// then on the vault cryptographically requires the PIN — a file/storage
  /// copy alone is not enough, unlike a UI-only gate. Setting a PIN disables
  /// the Hello gate (a single gate keeps the model simple); the hello marker
  /// is removed.
  Future<void> setPin(String? pin) async {
    final path = _vaultPath;
    if (path == null) return;
    if (pin == null || pin.isEmpty) {
      // Restore a plaintext device key so boot works without a PIN. If the
      // vault was never device-bound yet, leave it unbound.
      if (_devPass != null) await plat.secureWrite(path, 'devkey', _devPass!);
      await plat.secureDelete(path, 'pin'); // legacy marker
      lockMode =
          await plat.secureRead(path, 'hello') != null ? 'hello' : null;
    } else {
      var pw = _devPass;
      if (pw == null || pw.isEmpty) {
        pw = 'dev.${AlienApi.randomBytes(32)}';
        setVaultPassword(pw);
        _devPass = pw;
      }
      final wrapped = AlienApi.pinWrap(
          pin, base64Encode(utf8.encode(pw)));
      await plat.secureWrite(path, 'devkey', '$pinPrefix$wrapped');
      await plat.secureDelete(path, 'pin'); // legacy marker
      await plat.secureDelete(path, 'hello'); // PIN replaces the hello gate
      lockMode = 'pin';
    }
    notifyListeners();
  }

  /// Enable/disable Windows Hello / biometrics as the unlock gate.
  ///
  /// Enabling Hello while the device key is PIN-wrapped restores the plain
  /// device key (we hold it in memory — the vault is open): the two gates are
  /// mutually exclusive, and keeping the PIN wrap while the UI says "Hello"
  /// would still require the PIN at boot.
  Future<void> setHello(bool on) async {
    final path = _vaultPath;
    if (path == null) return;
    if (on) {
      final pw = _devPass;
      if (pw != null && await devkeyNeedsPin(path)) {
        await plat.secureWrite(path, 'devkey', pw);
      }
      await plat.secureWrite(path, 'hello', 'hello');
      lockMode = 'hello';
    } else {
      await plat.secureDelete(path, 'hello');
      lockMode = await detectLockMode(path);
    }
    notifyListeners();
  }

  /// Verify a PIN attempt. Legacy path (post-open gate): the marker stored
  /// `pin.<pin>` — checked, then transparently migrated to a PIN-wrapped
  /// device key so the vault itself becomes PIN-bound.
  Future<bool> checkPin(String pin) async {
    final path = _vaultPath;
    if (path == null) return false;
    try {
      if (await plat.secureRead(path, 'pin') == 'pin.$pin') {
        // Migrate: wrap the current device key under the PIN and drop the
        // plaintext-verifier marker.
        final pw = _devPass ?? await devicePassword(path);
        if (pw != null && pw.isNotEmpty && !pw.startsWith(pinPrefix)) {
          final wrapped =
              AlienApi.pinWrap(pin, base64Encode(utf8.encode(pw)));
          await plat.secureWrite(path, 'devkey', '$pinPrefix$wrapped');
          await plat.secureDelete(path, 'pin');
        }
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Generate a fresh single-use contact card (also persists its bundle).
  /// Returns the card blob rendered as text for sharing.
  String shareCard({String format = 'blob'}) {
    final r = AlienApi.cardCreate(identitySeed!);
    bundles.add(r['bundle'] as String);
    _persist();
    return AlienApi.render(r['card_envelope'] as String, format);
  }

  /// Raw card envelope bytes (b64) for QR encoding.
  String shareCardB64() {
    final r = AlienApi.cardCreate(identitySeed!);
    bundles.add(r['bundle'] as String);
    _persist();
    return r['card_envelope'] as String;
  }

  /// Pair with a contact: verify card, start session.
  Contact pairContact(String name, String peerCardB64) {
    final myCardB64 = _latestCardB64();
    final r = AlienApi.sessionStart(identitySeed!, myCardB64, peerCardB64);
    final c = Contact(
      name: name,
      pubId: r['peer_id'] as String,
      card: peerCardB64,
      session: r['session'] as String,
      sessionId: r['session_id'] as String,
    );
    contacts.removeWhere((x) => x.pubId == c.pubId);
    contacts.add(c);
    _persist();
    notifyListeners();
    return c;
  }

  String _latestCardB64() {
    // regenerate a card so every pairing uses fresh prekeys; the bundle is
    // persisted so peers targeting it can still pair back.
    final r = AlienApi.cardCreate(identitySeed!);
    bundles.add(r['bundle'] as String);
    _persist();
    return r['card'] as String;
  }

  String fingerprintFor(Contact c) => AlienApi.fingerprint(identitySeed!, c.card);

  void markVerified(Contact c, bool value) {
    c.verified = value;
    _persist();
    notifyListeners();
  }

  /// Encrypt `plaintext` to contact; returns rendered output text.
  String encryptFor(Contact c, String plaintext, String format) {
    if (c.session == null) throw StateError('contatto non abbinato');
    final r = AlienApi.encrypt(c.session!, plaintext);
    c.session = r['session'] as String;
    _persist();
    return AlienApi.render(r['envelope'] as String, format);
  }

  /// Encrypt to group; returns rendered output text.
  String encryptGroup(GroupChat g, String plaintext, String format) {
    final r = AlienApi.groupEncrypt(identitySeed!, g.blob, plaintext);
    g.blob = r['group'] as String;
    _persist();
    return AlienApi.render(r['envelope'] as String, format);
  }

  List<String> _sessionList() =>
      contacts.where((c) => c.session != null).map((c) => c.session!).toList();

  void _writeBackSessions(List<dynamic> sessions) {
    final paired = contacts.where((c) => c.session != null).toList();
    for (var i = 0; i < sessions.length && i < paired.length; i++) {
      paired[i].session = sessions[i] as String;
    }
  }

  /// An invite/rotate whose inner wrap was a PairInit established a pairwise
  /// session with the admin as a side effect. Attach it to that contact (or
  /// create it) so direct messaging works immediately, and drop the consumed
  /// one-time bundle.
  void _attachInnerSession(dynamic inner) {
    if (inner is! Map) return;
    final consumed = inner['consumed_bundle'];
    if (consumed is int && consumed >= 0 && consumed < bundles.length) {
      bundles.removeAt(consumed);
    }
    final peerId = inner['peer_id'] as String?;
    final sess = inner['session'] as String?;
    if (peerId == null || sess == null) return;
    final peerCard = inner['peer_card'] as String? ?? '';
    final idx = contacts.indexWhere((c) => c.pubId == peerId);
    if (idx >= 0) {
      contacts[idx].session = sess;
      contacts[idx].sessionId = inner['session_id'] as String?;
      if (peerCard.isNotEmpty) contacts[idx].card = peerCard;
    } else {
      contacts.add(Contact(
        name: 'Contatto ${peerId.substring(0, peerId.length < 8 ? peerId.length : 8)}',
        pubId: peerId,
        card: peerCard,
        session: sess,
        sessionId: inner['session_id'] as String?,
      ));
    }
  }

  void _writeBackGroups(List<dynamic> blobs) {
    for (var i = 0; i < blobs.length && i < groups.length; i++) {
      groups[i].blob = blobs[i] as String;
    }
  }

  /// Decode + dispatch any inbound text. Returns a human-readable result.
  InboundResult processInbound(String input) {
    final envB64 = AlienApi.unrender(input);
    final r = AlienApi.decrypt(
      identityB64: identitySeed!,
      bundlesB64: bundles,
      sessionsB64: _sessionList(),
      groupsB64: groups.map((g) => g.blob).toList(),
      envelopeB64: envB64,
    );
    final kind = r['kind'] as String;
    switch (kind) {
      case 'card':
        return InboundResult('card', r['card'] as String,
            peerId: r['owner_id'] as String);
      case 'new_session':
        {
          final peerId = r['peer_id'] as String;
          final peerCard = r['peer_card'] as String? ?? '';
          // The one-time prekey bundle targeted by this handshake has been
          // consumed: dropping it improves forward secrecy of the pairing.
          final consumed = r['consumed_bundle'];
          if (consumed is int && consumed >= 0 && consumed < bundles.length) {
            bundles.removeAt(consumed);
          }
          final idx = contacts.indexWhere((c) => c.pubId == peerId);
          if (idx >= 0) {
            contacts[idx].session = r['session'] as String;
            contacts[idx].sessionId = r['session_id'] as String?;
            if (peerCard.isNotEmpty) contacts[idx].card = peerCard;
          } else {
            contacts.add(Contact(
              name: 'Contatto ${peerId.substring(0, 8)}',
              pubId: peerId,
              card: peerCard,
              session: r['session'] as String,
              sessionId: r['session_id'] as String?,
            ));
          }
          _persist();
          notifyListeners();
          return InboundResult('text', r['plaintext'] as String,
              peerId: peerId);
        }
      case 'pair':
        {
          _writeBackSessions(r['sessions'] as List);
          _persist();
          notifyListeners();
          return InboundResult('text', r['plaintext'] as String,
              peerId: r['peer_id'] as String);
        }
      case 'group_joined':
        {
          final gid = r['group_id'] as String;
          final name = r['name'] as String?;
          groups.add(GroupChat(
            name: (name != null && name.isNotEmpty)
                ? name
                : 'Gruppo ${gid.substring(0, 8)}',
            groupId: gid,
            blob: r['group'] as String,
          ));
          _writeBackSessions(r['sessions'] as List);
          _attachInnerSession(r['inner_session']);
          _persist();
          notifyListeners();
          return InboundResult('info',
              'Sei entrato nel gruppo "${groups.last.name}"',
              groupId: r['group_id'] as String);
        }
      case 'group_rotated':
        {
          _writeBackGroups(r['groups'] as List);
          _writeBackSessions(r['sessions'] as List);
          _attachInnerSession(r['inner_session']);
          _persist();
          notifyListeners();
          return InboundResult('info', 'Chiave di gruppo ruotata');
        }
      case 'group_text':
        {
          _writeBackGroups(r['groups'] as List);
          _persist();
          notifyListeners();
          return InboundResult('group_text', r['plaintext'] as String,
              peerId: r['sender'] as String);
        }
      default:
        return InboundResult('info', 'Tipo sconosciuto: $kind');
    }
  }

  /// Create a group; returns invite envelope text to paste to members.
  String createGroup(String name, List<String> memberPubIds) {
    final r = AlienApi.groupCreate(
      identityB64: identitySeed!,
      sessionsB64: _sessionList(),
      memberIdsHex: memberPubIds,
      name: name,
    );
    _writeBackSessions(r['sessions'] as List);
    groups.add(GroupChat(
        name: name, groupId: r['group_id'] as String, blob: r['group'] as String));
    _persist();
    notifyListeners();
    return AlienApi.render(r['envelope'] as String, 'blob');
  }

  /// Rotate group key keeping `keepPubIds` (+ admin). Returns rotate blob text.
  String rotateGroup(GroupChat g, List<String> keepPubIds) {
    final keep = keepPubIds.toSet()..add(pubId!);
    final r = AlienApi.groupRotate(
      identityB64: identitySeed!,
      groupB64: g.blob,
      sessionsB64: _sessionList(),
      newMembersHex: keep.toList(),
    );
    g.blob = r['group'] as String;
    _writeBackSessions(r['sessions'] as List);
    _persist();
    notifyListeners();
    return AlienApi.render(r['envelope'] as String, 'blob');
  }

  // --- chat history (kept in the encrypted vault) ---

  static String historyKeyForContact(String pubId) => 'hist.p.$pubId';
  static String historyKeyForGroup(String groupId) => 'hist.g.$groupId';

  /// Load the stored bubbles for a conversation (newest last, max 200).
  List<ChatEntry> history(String key) {
    final v = _vault;
    if (v == null) return [];
    return _decodeVaultJson<List<ChatEntry>>(
            AlienApi.vaultGet(v, key),
            (j) => (j as List)
                .map((e) => ChatEntry.fromJson(e as Map<String, dynamic>))
                .toList()) ??
        [];
  }

  /// Append a bubble to the conversation and persist it (FIFO cap 200).
  void logMessage(String key, ChatEntry entry) {
    final v = _vault;
    if (v == null) return;
    final list = history(key)..add(entry);
    final trimmed =
        list.length > 200 ? list.sublist(list.length - 200) : list;
    try {
      AlienApi.vaultSet(
          v, key, base64Encode(utf8.encode(jsonEncode(trimmed))));
      if (_vaultPath != null) AlienApi.vaultSave(v, _vaultPath!);
      if (persistFailed) {
        persistFailed = false;
        notifyListeners();
      }
    } catch (_) {
      if (!persistFailed) {
        persistFailed = true;
        notifyListeners();
      }
    }
  }

  /// Reload vault state after another browser tab changed it (web only —
  /// wired via [plat.onVaultChanged]). The wasm vault handle is in-memory,
  /// so we close and reopen from storage with the password we already hold.
  Future<void> reloadFromStorage() async {
    final path = _vaultPath;
    final pw = _devPass;
    final v = _vault;
    if (path == null || pw == null) return;
    try {
      if (v != null) AlienApi.vaultClose(v);
      final r = AlienApi.vaultOpen(path, pw);
      _vault = r['handle'] as int;
      vaultProtected = r['protected'] == true;
      _load();
      notifyListeners();
    } catch (_) {}
  }

  /// Whether the one-time "salva la frase di recupero" banner was dismissed.
  bool get backupDismissed {
    final v = _vault;
    if (v == null) return true;
    return AlienApi.vaultGet(v, 'backup_dismissed') != null;
  }

  void dismissBackupReminder() {
    final v = _vault;
    if (v == null) return;
    try {
      AlienApi.vaultSet(v, 'backup_dismissed', 'MQ=='); // '1'
      if (_vaultPath != null) AlienApi.vaultSave(v, _vaultPath!);
    } catch (_) {}
    notifyListeners();
  }

  /// Remove a contact together with its session state (the session blob is
  /// dropped from the vault on the next persist — forward secrecy by deletion).
  void deleteContact(Contact c) {
    contacts.removeWhere((x) => x.pubId == c.pubId);
    final v = _vault;
    if (v != null) AlienApi.vaultRemove(v, historyKeyForContact(c.pubId));
    _persist();
    notifyListeners();
  }

  /// Remove a group locally. Other members are NOT notified — the group admin
  /// should rotate the key without us to actually revoke read access.
  void deleteGroup(GroupChat g) {
    groups.removeWhere((x) => x.groupId == g.groupId);
    final v = _vault;
    if (v != null) AlienApi.vaultRemove(v, historyKeyForGroup(g.groupId));
    _persist();
    notifyListeners();
  }

  /// Close the vault AND delete the vault file. Without the delete the
  /// identity seed would stay on disk (decryptable for plain v1 vaults),
  /// which would make "Cancella dati" a lie.
  Future<void> wipe() async {
    if (_vault != null) AlienApi.vaultClose(_vault!);
    _vault = null;
    _devPass = null;
    _locked = false;
    _gated = false;
    needsPinToOpen = false;
    persistFailed = false;
    vaultProtected = false;
    identitySeed = null;
    pubId = null;
    recoveryPhrase = null;
    lockMode = null;
    bundles = [];
    contacts = [];
    groups = [];
    final path = _vaultPath;
    if (path != null) {
      try {
        AlienApi.vaultDelete(path);
      } catch (_) {}
      for (final name in ['devkey', 'devkey.tmp', 'pin', 'hello']) {
        try {
          await plat.secureDelete(path, name);
        } catch (_) {}
      }
      // Reopen a fresh vault so the next identity creation can persist —
      // otherwise the store would sit on a null vault and never save.
      try {
        final r = AlienApi.vaultOpen(path, '');
        _vault = r['handle'] as int;
        vaultProtected = r['protected'] == true;
      } catch (_) {}
    }
    notifyListeners();
  }
}

final store = Store();
