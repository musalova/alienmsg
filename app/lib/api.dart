import 'ffi.dart';

/// High-level operations over the alien-ffi JSON API.
class AlienApi {
  static Future<String> generateMnemonic() async =>
      AlienFfi.call({'op': 'mnemonic_generate'})['mnemonic'] as String;

  static bool validateMnemonic(String phrase) =>
      AlienFfi.call({'op': 'mnemonic_validate', 'phrase': phrase})['valid'] ==
      true;

  /// Returns {identity (b64 seed), pub_id, ed_pub, x_pub}.
  static Map<String, dynamic> identityCreate(String mnemonic,
      [String passphrase = '']) {
    return AlienFfi.call({
      'op': 'identity_create',
      'mnemonic': mnemonic,
      'passphrase': passphrase,
    });
  }

  /// Returns {card_envelope, card, bundle, card_id, owner_id}.
  static Map<String, dynamic> cardCreate(String identityB64) =>
      AlienFfi.call({'op': 'card_create', 'identity': identityB64});

  static String fingerprint(String identityB64, String peerCardB64) =>
      AlienFfi.call({
        'op': 'fingerprint',
        'identity': identityB64,
        'peer_card': peerCardB64,
      })['sas'] as String;

  /// Returns {session, session_id, peer_id}.
  static Map<String, dynamic> sessionStart(
          String identityB64, String myCardB64, String peerCardB64) =>
      AlienFfi.call({
        'op': 'session_start',
        'identity': identityB64,
        'my_card': myCardB64,
        'peer_card': peerCardB64,
      });

  /// Returns {session (updated), envelope}.
  static Map<String, dynamic> encrypt(String sessionB64, String plaintext) =>
      AlienFfi.call(
          {'op': 'encrypt', 'session': sessionB64, 'plaintext': plaintext});

  /// Full inbound dispatch. Returns {kind, ...} — see alien-ffi for fields.
  static Map<String, dynamic> decrypt({
    required String identityB64,
    required List<String> bundlesB64,
    required List<String> sessionsB64,
    required List<String> groupsB64,
    required String envelopeB64,
  }) =>
      AlienFfi.call({
        'op': 'decrypt',
        'identity': identityB64,
        'bundles': bundlesB64,
        'sessions': sessionsB64,
        'groups': groupsB64,
        'envelope': envelopeB64,
      });

  /// Returns {group, group_id, envelope, sessions}.
  static Map<String, dynamic> groupCreate({
    required String identityB64,
    required List<String> sessionsB64,
    required List<String> memberIdsHex,
    required String name,
  }) =>
      AlienFfi.call({
        'op': 'group_create',
        'identity': identityB64,
        'sessions': sessionsB64,
        'member_ids': memberIdsHex,
        'name': name,
      });

  /// Returns {group, envelope, sessions}.
  static Map<String, dynamic> groupRotate({
    required String identityB64,
    required String groupB64,
    required List<String> sessionsB64,
    required List<String> newMembersHex,
  }) =>
      AlienFfi.call({
        'op': 'group_rotate',
        'identity': identityB64,
        'group': groupB64,
        'sessions': sessionsB64,
        'new_members': newMembersHex,
      });

  /// Returns {group_id, epoch, name, members: [{id, is_me, is_admin}]}.
  static Map<String, dynamic> groupInfo(String groupB64) =>
      AlienFfi.call({'op': 'group_info', 'group': groupB64});

  /// Returns {group (updated), envelope}.
  static Map<String, dynamic> groupEncrypt(String groupB64, String plaintext) =>
      AlienFfi.call(
          {'op': 'group_encrypt', 'group': groupB64, 'plaintext': plaintext});

  /// format: 'blob' | 'emoji' | 'words'
  static String render(String bytesB64, String format) =>
      AlienFfi.call({'op': 'render', 'bytes': bytesB64, 'format': format})[
          'text'] as String;

  /// Returns raw envelope bytes (b64) from any supported text format.
  static String unrender(String text) =>
      AlienFfi.call({'op': 'unrender', 'text': text})['bytes'] as String;

  // --- vault ---

  static int vaultOpen(String path, String password) =>
      AlienFfi.call({'op': 'vault_open', 'path': path, 'password': password})[
          'handle'] as int;

  static void vaultSet(int handle, String key, String valueB64) =>
      AlienFfi.call(
          {'op': 'vault_set', 'handle': handle, 'key': key, 'value': valueB64});

  static String? vaultGet(int handle, String key) =>
      AlienFfi.call({'op': 'vault_get', 'handle': handle, 'key': key})['value']
          as String?;

  static List<String> vaultList(int handle, String prefix) =>
      (AlienFfi.call(
                  {'op': 'vault_list', 'handle': handle, 'prefix': prefix})[
              'keys'] as List)
          .cast<String>();

  static void vaultRemove(int handle, String key) => AlienFfi.call(
      {'op': 'vault_remove', 'handle': handle, 'key': key});

  static void vaultSave(int handle, String path) => AlienFfi.call(
      {'op': 'vault_save', 'handle': handle, 'path': path});

  static void vaultClose(int handle) =>
      AlienFfi.call({'op': 'vault_close', 'handle': handle});
}
