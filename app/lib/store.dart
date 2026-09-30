import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'api.dart';

class Contact {
  String name;
  final String pubId; // hex owner id from their card
  final String card; // b64 postcard ContactCard
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
        pubId: j['pub_id'],
        card: j['card'],
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
  static GroupChat fromJson(Map<String, dynamic> j) =>
      GroupChat(name: j['name'] ?? '', groupId: j['group_id'], blob: j['blob']);
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

  String? identitySeed; // b64 seed
  String? pubId; // hex
  List<String> bundles = []; // b64 CardBundles
  List<Contact> contacts = [];
  List<GroupChat> groups = [];

  bool get isOpen => _vault != null;
  bool get hasIdentity => identitySeed != null;

  static Future<String> defaultVaultPath() async {
    final dir = await getApplicationSupportDirectory();
    return '${dir.path}${Platform.pathSeparator}alienmsg.vault';
  }

  Future<void> open(String path, String password) async {
    _vault = AlienApi.vaultOpen(path, password);
    _vaultPath = path;
    _load();
  }

  void _load() {
    identitySeed = AlienApi.vaultGet(_vault!, 'identity');
    final meta = AlienApi.vaultGet(_vault!, 'meta');
    pubId = meta == null ? null : (jsonDecode(utf8.decode(base64Decode(meta)))['pub_id'] as String?);
    final bundlesJson = AlienApi.vaultGet(_vault!, 'bundles');
    bundles = bundlesJson == null
        ? []
        : (jsonDecode(utf8.decode(base64Decode(bundlesJson))) as List)
            .cast<String>();
    final contactsJson = AlienApi.vaultGet(_vault!, 'contacts');
    contacts = contactsJson == null
        ? []
        : (jsonDecode(utf8.decode(base64Decode(contactsJson))) as List)
            .map((e) => Contact.fromJson(e))
            .toList();
    final groupsJson = AlienApi.vaultGet(_vault!, 'groups');
    groups = groupsJson == null
        ? []
        : (jsonDecode(utf8.decode(base64Decode(groupsJson))) as List)
            .map((e) => GroupChat.fromJson(e))
            .toList();
    notifyListeners();
  }

  void _persist() {
    final v = _vault!;
    if (identitySeed != null) AlienApi.vaultSet(v, 'identity', identitySeed!);
    AlienApi.vaultSet(
        v,
        'meta',
        base64Encode(utf8.encode(jsonEncode({'pub_id': pubId}))));
    AlienApi.vaultSet(v, 'bundles', base64Encode(utf8.encode(jsonEncode(bundles))));
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
  }

  void createIdentity(String mnemonic, String passphrase) {
    final r = AlienApi.identityCreate(mnemonic, passphrase);
    identitySeed = r['identity'] as String;
    pubId = r['pub_id'] as String;
    _persist();
    notifyListeners();
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
    final r = AlienApi.groupEncrypt(g.blob, plaintext);
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
          final idx = contacts.indexWhere((c) => c.pubId == peerId);
          if (idx >= 0) {
            contacts[idx].session = r['session'] as String;
          } else {
            contacts.add(Contact(
              name: 'Contatto ${peerId.substring(0, 8)}',
              pubId: peerId,
              card: '', // we don't have their card blob here; pairing material came via init
              session: r['session'] as String,
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
          groups.add(GroupChat(
            name: 'Gruppo ${(r['group_id'] as String).substring(0, 8)}',
            groupId: r['group_id'] as String,
            blob: r['group'] as String,
          ));
          _writeBackSessions(r['sessions'] as List);
          _persist();
          notifyListeners();
          return InboundResult('info', 'Aggiunto al gruppo',
              groupId: r['group_id'] as String);
        }
      case 'group_rotated':
        {
          _writeBackGroups(r['groups'] as List);
          _writeBackSessions(r['sessions'] as List);
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

  void wipe() {
    // Overwrite-and-remove is best-effort on flash storage; the vault itself
    // is encrypted, so deleting the file plus closing suffices for app-level
    // hygiene.
    if (_vault != null) AlienApi.vaultClose(_vault!);
    _vault = null;
    identitySeed = null;
    pubId = null;
    bundles = [];
    contacts = [];
    groups = [];
    notifyListeners();
  }
}

final store = Store();
