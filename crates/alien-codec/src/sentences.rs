//! Cover text: ciphertext rendered as grammatically correct but meaningless
//! Italian sentences. One data word carries exactly one byte; articles,
//! prepositions and conjunctions are structural fillers the decoder skips.
//!
//! Opacity, not security: the AEAD payload underneath is already random
//! noise. This just makes a pasted transcript look like odd prose instead
//! of a blob.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::CodecError;

// ---------------------------------------------------------------------------
// Wordlists. Every slot word encodes one byte: index == byte value, so each
// list must contain exactly 256 entries (compile-time enforced by the
// `[..256]` const slices below) and all words must be globally unique and
// distinct from CARRIERS (test-enforced).
// ---------------------------------------------------------------------------

const NM_FULL: &[&str] = &[
    // 256 masculine nouns
    "tempo", "giorno", "uomo", "mondo", "lavoro", "paese", "momento", "modo",
    "anno", "punto", "nome", "posto", "amico", "libro", "padre", "figlio",
    "fratello", "signore", "campo", "occhio", "viaggio", "pensiero", "sole", "mare",
    "vento", "cuore", "cane", "gatto", "albero", "fiore", "pane", "vino",
    "zucchero", "sale", "riso", "grano", "orto", "prato", "bosco", "fiume",
    "lago", "monte", "colle", "ponte", "muro", "tetto", "tavolo", "letto",
    "divano", "telefono", "computer", "quaderno", "foglio", "zaino", "orologio",
    "specchio", "armadio", "frigorifero", "forno", "balcone", "giardino", "cortile",
    "viale", "sentiero", "binario", "porto", "faro", "treno", "aereo", "autobus",
    "tram", "motore", "volante", "casco", "guanto", "cappotto", "maglione", "cappello",
    "vestito", "calzino", "stivale", "ombrello", "giornale", "film", "museo", "teatro",
    "cinema", "concerto", "quadro", "ritratto", "disegno", "colore", "pennello",
    "scalpello", "martello", "chiodo", "filo", "ago", "tessuto", "medico",
    "dottore", "maestro", "studente", "operaio", "muratore", "pittore", "barista",
    "cuoco", "panettiere", "falegname", "giardiniere", "contadino", "pescatore",
    "marinaio", "pilota", "cantante", "musicista", "attore", "regista", "scrittore",
    "poeta", "giornalista", "fotografo", "meccanico", "elettricista", "idraulico",
    "fornaio", "macellaio", "salumiere", "fruttivendolo", "libraio", "ragazzo",
    "bambino", "nonno", "zio", "cugino", "nipote", "marito", "compagno",
    "vicino", "conoscente", "collega", "capo", "cliente", "paziente", "ospite",
    "turista", "poliziotto", "vigile", "soldato", "generale", "capitano", "sindaco",
    "senatore", "deputato", "giudice", "avvocato", "notaio", "commercialista",
    "ragioniere", "impiegato", "direttore", "segretario", "mago", "folletto", "gnomo",
    "gigante", "cavaliere", "pirata", "guerriero", "esploratore", "inventore",
    "scienziato", "astronauta", "archeologo", "botanico", "geologo", "astronomo",
    "matematico", "leone", "lupo", "orso", "cervo", "cinghiale", "scoiattolo",
    "riccio", "tasso", "falco", "gufo", "corvo", "merlo", "picchio", "piccione",
    "gabbiano", "pappagallo", "pavone", "serpente", "coccodrillo", "alligatore",
    "elefante", "ippopotamo", "rinoceronte", "gorilla", "macaco", "canguro", "koala",
    "panda", "lama", "alpaca", "cammello", "dromedario", "bufalo", "cavallo",
    "asino", "mulo", "bue", "toro", "vitello", "agnello", "capretto", "maiale",
    "coniglio", "gallo", "tacchino", "pinguino", "struzzo", "fenicottero", "airone",
    "cigno", "pellicano", "pianoforte", "violino", "mandolino", "violoncello",
    "contrabbasso", "flauto", "clarinetto", "oboe", "fagotto", "trombone", "corno",
    "organo", "tamburo", "piatto", "gong", "triangolo", "xilofono", "sassofono",
    "clarino", "basso", "pianeta", "satellite", "razzo", "universo", "cosmo",
    "cielo", "spazio", "atomo", "protone", "elettrone", "neutrone", "fotone",
    "cristallo", "diamante", "smeraldo", "rubino", "topazio", "quarzo", "marmo",
    "granito", "basalto", "ciottolo", "masso", "macigno", "scoglio", "ghiacciaio",
];

const NF_FULL: &[&str] = &[
    // 256 feminine nouns
    "casa", "notte", "sera", "mattina", "settimana", "estate", "primavera", "giornata",
    "serata", "vita", "mano", "porta", "finestra", "strada", "piazza", "chiesa",
    "scuola", "bottega", "farmacia", "libreria", "pasticceria", "gelateria",
    "trattoria", "osteria", "locanda", "pensione", "spiaggia", "scogliera", "duna",
    "collina", "valle", "grotta", "caverna", "cascata", "sorgente", "fontana", "riva",
    "sponda", "costa", "isola", "penisola", "laguna", "baia", "cala", "radura",
    "pineta", "vigna", "campagna", "foresta", "palude", "brughiera", "landa",
    "macchia", "siepe", "aiuola", "terrazza", "veranda", "soffitta", "cantina",
    "mansarda", "stanza", "camera", "cucina", "sala", "anticamera", "corridoio",
    "scala", "nicchia", "parete", "tenda", "moquette", "poltrona", "sedia",
    "panca", "credenza", "vetrina", "mensola", "lampada", "lanterna", "candela",
    "fiamma", "brace", "cenere", "neve", "pioggia", "grandine", "nebbia", "foschia",
    "nuvola", "tempesta", "bufera", "aurora", "alba", "eclissi", "cometa", "stella",
    "galassia", "nebulosa", "orbita", "costellazione", "luna", "terra", "acqua",
    "aria", "vampa", "luce", "ombra", "voce", "musica", "melodia", "canzone",
    "sinfonia", "ballata", "nanna", "poesia", "favola", "leggenda", "storia",
    "cronaca", "lettera", "cartolina", "busta", "pagina", "riga", "parola",
    "frase", "firma", "nota", "lista", "spesa", "ricetta", "minestra", "zuppa",
    "pasta", "pizza", "focaccia", "torta", "crostata", "marmellata", "confettura",
    "crema", "cioccolata", "caramella", "frutta", "verdura", "carne", "arancia",
    "mela", "pera", "banana", "fragola", "ciliegia", "pesca", "albicocca", "prugna",
    "uva", "melagrana", "susina", "noce", "nocciola", "mandorla", "castagna",
    "oliva", "zucchina", "melanzana", "patata", "carota", "cipolla", "zucca",
    "lattuga", "cicoria", "bietola", "verza", "barbabietola", "rapa", "porro",
    "imposta", "penna", "matita", "gomma", "lavagna", "squadra", "calcolatrice",
    "agenda", "rubrica", "cornice", "fotografia", "istantanea", "polaroid", "pellicola",
    "videocamera", "macchina", "bicicletta", "motocicletta", "automobile", "carrozza",
    "diligenza", "nave", "barca", "canoa", "zattera", "fune", "vela", "funivia",
    "seggiovia", "metropolitana", "ferrovia", "stazione", "fermata", "banchina",
    "biglietteria", "edicola", "tabaccheria", "cartoleria", "merceria", "sartoria",
    "lavanderia", "stireria", "tintoria", "calzoleria", "pelletteria", "oreficeria",
    "gioielleria", "orologeria", "ottica", "erboristeria", "profumeria", "modisteria",
    "signora", "ragazza", "bambina", "nonna", "zia", "cugina", "moglie", "compagna",
    "vicina", "dottoressa", "maestra", "studentessa", "professoressa", "infermiera",
    "cuoca", "pasticcera", "cameriera", "commessa", "parrucchiera", "estetista",
    "ballerina", "attrice", "regina", "principessa", "duchessa", "contessa",
    "baronessa", "governante",
];

const V_FULL: &[&str] = &[
    // 256 verbs, 3rd person singular present
    "corre", "cammina", "dorme", "mangia", "beve", "legge", "scrive", "canta",
    "balla", "nuota", "vola", "salta", "ride", "piange", "sorride", "parla",
    "ascolta", "guarda", "osserva", "studia", "lavora", "gioca", "soffrigge", "pulisce",
    "lava", "stira", "cuce", "ripara", "costruisce", "dipinge", "disegna", "scolpisce",
    "suona", "recita", "fotografa", "filma", "guida", "viaggia", "naviga", "rema",
    "ripesca", "risale", "scava", "pianta", "raccoglie", "semina", "taglia", "pota",
    "innaffia", "spazza", "rastrella", "vanga", "zappa", "ara", "falcia", "miete",
    "trebbia", "macina", "impasta", "lievita", "cuoce", "bolle", "frigge",
    "arrostisce", "griglia", "condisce", "insaporisce", "assaggia", "sorseggia",
    "mastica", "respira", "sospira", "sbadiglia", "tossisce", "starnutisce", "trema",
    "freme", "brilla", "splende", "risplende", "luccica", "lampeggia", "sfavilla",
    "arde", "fiammeggia", "brucia", "scintilla", "illumina", "oscura", "annebbia",
    "offusca", "solca", "copre", "scopre", "apre", "chiude", "serra", "spalanca",
    "socchiude", "accosta", "scosta", "spinge", "tira", "trascina", "attrae",
    "respinge", "accoglie", "riceve", "dona", "offre", "regala", "vende", "compra",
    "paga", "spende", "guadagna", "risparmia", "investe", "conta", "misura", "pesa",
    "confronta", "paragona", "differisce", "somiglia", "distingue", "confonde",
    "chiarisce", "spiega", "narra", "racconta", "descrive", "immagina", "sogna",
    "pensa", "riflette", "medita", "ragiona", "pondera", "calcola", "suppone",
    "presume", "ipotizza", "deduce", "conclude", "decide", "risolve", "risponde",
    "domanda", "chiede", "interroga", "dubita", "sospetta", "teme", "spera",
    "confida", "crede", "ammira", "adora", "venera", "abbraccia", "bacia",
    "accarezza", "coccola", "protegge", "difende", "custodisce", "sorveglia",
    "veglia", "attende", "aspetta", "sosta", "indugia", "tarda", "accelera",
    "rallenta", "procede", "avanza", "retrocede", "marcia", "incede", "passeggia",
    "bighellona", "vagabonda", "vaga", "erra", "gira", "ruota", "volteggia",
    "saltella", "sgambetta", "zampetta", "trotta", "galoppa", "sguazza", "scivola",
    "plana", "veleggia", "fluttua", "galleggia", "affonda", "emerge", "riemerge",
    "sprofonda", "precipita", "casca", "cade", "rotola", "ruzzola", "dondola",
    "oscilla", "vibra", "ondeggia", "palpita", "pulsa", "batte", "rintocca",
    "echeggia", "risuona", "rimbomba", "ruggisce", "ulula", "miagola", "abbaia",
    "latra", "ringhia", "guaisce", "nitrisce", "raglia", "muggisce", "starnazza",
    "squittisce", "tuba", "gorgheggia", "cinguetta", "trilla", "fischietta",
    "zufola", "borbotta", "mormora", "bisbiglia", "sussurra", "farfuglia",
    "balbetta", "tartaglia", "sbraita", "strilla", "urla", "grida", "schiamazza",
    "vocia", "chiacchiera", "cicala", "declama", "detta", "annota", "segna",
    "registra", "trascrive", "copia", "incolla", "cancella", "corregge",
    "sottolinea", "evidenzia", "cerchia", "circonda", "racchiude", "include",
    "esclude", "aggiunge", "toglie", "leva", "sottrae", "moltiplica", "divide",
];

const AV_FULL: &[&str] = &[
    // 256 adverbs / adverbials
    "lentamente", "velocemente", "dolcemente", "piano", "forte", "sempre", "mai",
    "spesso", "raramente", "oggi", "domani", "ieri", "presto", "tardi", "adesso",
    "ora", "subito", "ancora", "già", "appena", "quasi", "davvero", "certo",
    "sicuramente", "probabilmente", "naturalmente", "ovviamente", "normalmente",
    "generalmente", "solitamente", "abitualmente", "frequentemente", "occasionalmente",
    "improvvisamente", "immediatamente", "gradualmente", "silenziosamente",
    "tranquillamente", "pacificamente", "felicemente", "allegramente", "tristemente",
    "malinconicamente", "nervosamente", "ansiosamente", "coraggiosamente",
    "timidamente", "audacemente", "prudentemente", "cautamente", "attentamente",
    "distrattamente", "curiosamente", "pigramente", "diligentemente", "energicamente",
    "vivacemente", "rapidamente", "facilmente", "difficilmente", "semplicemente",
    "chiaramente", "oscuramente", "brillantemente", "opacamente", "leggermente",
    "pesantemente", "amaramente", "teneramente", "aspramente", "duramente",
    "gentilmente", "cortesemente", "educatamente", "bruscamente", "freddamente",
    "caldamente", "tiepidamente", "gelidamente", "ardentemente", "appassionatamente",
    "indifferentemente", "serenamente", "pazientemente", "impazientemente",
    "saggiamente", "follemente", "stupidamente", "intelligentemente", "genialmente",
    "furbamente", "ingenuamente", "candidamente", "apertamente", "schiettamente",
    "sinceramente", "onestamente", "lealmente", "fedelmente", "falsamente",
    "ipocritamente", "vigliaccamente", "codardamente", "valorosamente", "eroicamente",
    "nobilmente", "umilmente", "modestamente", "orgogliosamente", "superbamente",
    "arrogantemente", "presuntuosamente", "vanamente", "vanitosamente", "graziosamente",
    "goffamente", "elegantemente", "rozzamente", "finemente", "grossolanamente",
    "delicatamente", "fragilmente", "solidamente", "robustamente", "debolmente",
    "fiaccamente", "vigorosamente", "possentemente", "laboriosamente",
    "instancabilmente", "infaticabilmente", "indefessamente", "strenuamente",
    "meticolosamente", "scrupolosamente", "precisamente", "esattamente",
    "accuratamente", "approssimativamente", "vagamente", "confusamente",
    "ordinatamente", "disordinatamente", "caoticamente", "metodicamente",
    "sistematicamente", "casualmente", "fortuitamente", "deliberatamente",
    "volontariamente", "involontariamente", "inconsciamente", "consciamente",
    "consapevolmente", "inconsapevolmente", "scientemente", "spontaneamente",
    "istintivamente", "razionalmente", "logicamente", "illogicamente", "assurdamente",
    "ragionevolmente", "irragionevolmente", "sensatamente", "insensatamente",
    "sagacemente", "accortamente", "avvedutamente", "sconsideratamente",
    "incautamente", "imprudentemente", "temerariamente", "spericolatamente",
    "rischiosamente", "avventurosamente", "sfrontatamente", "sfacciatamente",
    "impudentemente", "improntemente", "riservatamente", "discretamente",
    "indiscretamente", "segretamente", "palesemente", "velatamente",
    "copertamente", "furtivamente", "dirottamente", "direttamente",
    "indirettamente", "obliquamente", "trasversalmente", "lateralmente",
    "frontalmente", "verticalmente", "orizzontalmente", "dritto", "storto",
    "pari", "dispari", "avanti", "indietro", "sopra", "sotto", "dentro",
    "fuori", "pressoché", "lontano", "accanto", "intorno", "attorno",
    "dappertutto", "ovunque", "altrove", "lassù", "laggiù", "quassù", "quaggiù",
    "perfino", "persino", "addirittura", "appunto", "infatti", "anzi", "invece",
    "altrimenti", "piuttosto", "abbastanza", "talmente", "tanto", "così",
    "precipitosamente", "frettolosamente", "pacatamente", "quietamente",
    "placidamente", "bonariamente", "burberamente", "arcignamente", "blandamente",
    "veementemente", "violentemente", "ferocemente", "mitemente", "durevolmente",
    "efficacemente", "efficientemente", "inefficientemente", "effettivamente",
    "puntualmente", "giustamente", "ingiustamente", "equamente", "iniquamente",
    "parzialmente",
];

/// Structural tokens the encoder may emit; they carry no data and the decoder
/// skips them. Must stay disjoint from every wordlist (test-enforced).
const CARRIERS: &[&str] = &[
    "il", "lo", "la", "l", "i", "gli", "le", "un", "uno", "una", "del", "dello",
    "della", "dell", "dei", "degli", "delle", "al", "allo", "alla", "all", "dal",
    "dallo", "dalla", "dall", "nel", "nello", "nella", "nell", "sul", "sullo",
    "sulla", "sull", "col", "coi", "di", "a", "ad", "da", "in", "con", "su",
    "per", "tra", "fra", "verso", "dopo", "prima", "durante", "mentre", "ogni",
    "quando", "dove", "come", "e", "ed", "ma", "che", "se", "non", "ecco",
    "poi", "quindi", "dunque", "però", "tuttavia",
];

/// Indexable views: exactly the first 256 entries of each list (asserted in
/// tests; words beyond that bound are never emitted nor decodable).
fn nm_list() -> &'static [&'static str] {
    &NM_FULL[..256.min(NM_FULL.len())]
}
fn nf_list() -> &'static [&'static str] {
    &NF_FULL[..256.min(NF_FULL.len())]
}
fn v_list() -> &'static [&'static str] {
    &V_FULL[..256.min(V_FULL.len())]
}
fn av_list() -> &'static [&'static str] {
    &AV_FULL[..256.min(AV_FULL.len())]
}

fn is_vowel(c: char) -> bool {
    matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'à' | 'è' | 'é' | 'ì' | 'ò' | 'ù')
}

fn starts_vowel(w: &str) -> bool {
    w.chars().next().is_some_and(is_vowel)
}

/// s+consonant / gn / ps / x / z initial clusters take "lo"-type articles.
fn starts_impure(w: &str) -> bool {
    let mut it = w.chars();
    match it.next() {
        Some('s') => it.next().is_some_and(|c| !is_vowel(c)),
        Some('g') => it.next() == Some('n'),
        Some('p') => it.next() == Some('s'),
        Some('z' | 'x' | 'y') => true,
        _ => false,
    }
}

/// Detached article forms (used mid-sentence before a known word).
fn det_m(n: &str) -> &'static str {
    if starts_vowel(n) { "l'" } else if starts_impure(n) { "lo" } else { "il" }
}
fn det_f(n: &str) -> &'static str {
    if starts_vowel(n) { "l'" } else { "la" }
}
fn ind_m(n: &str) -> &'static str {
    if starts_vowel(n) { "un" } else if starts_impure(n) { "uno" } else { "un" }
}
fn nel_m(n: &str) -> &'static str {
    if starts_vowel(n) { "nell'" } else if starts_impure(n) { "nello" } else { "nel" }
}

/// Join article+noun honouring apostrophe forms ("l'" + "albero").
fn j<'a>(art: &'static str, noun: &'a str) -> String {
    if art.ends_with('\'') {
        format!("{art}{noun}")
    } else {
        format!("{art} {noun}")
    }
}

fn cap(s: &str) -> String {
    let mut it = s.chars();
    match it.next() {
        Some(f) => f.to_uppercase().collect::<String>() + it.as_str(),
        None => String::new(),
    }
}

/// Byte source: each take() consumes exactly one byte → one slot word.
struct Puller<'a> {
    it: core::slice::Iter<'a, u8>,
}
impl<'a> Puller<'a> {
    fn take(&mut self) -> usize {
        *self.it.next().unwrap_or(&0) as usize
    }
    fn nm(&mut self) -> &'static str {
        nm_list()[self.take()]
    }
    fn nf(&mut self) -> &'static str {
        nf_list()[self.take()]
    }
    fn v(&mut self) -> &'static str {
        v_list()[self.take()]
    }
    fn av(&mut self) -> &'static str {
        av_list()[self.take()]
    }
}

// Frames keyed by how many data words they consume (1..=7). Bytes must be
// pulled strictly in left-to-right text order: decode maps each dictionary
// word back to the byte it replaced.
fn frame1(w: &mut Puller) -> String {
    let n = w.nm();
    format!("Ecco {}.", j(det_m(n), n))
}
fn frame2(w: &mut Puller) -> String {
    let n = w.nf();
    let v = w.v();
    format!("{} {}.", j(det_f(n), n), v)
}
fn frame3(w: &mut Puller) -> String {
    let n = w.nm();
    let v = w.v();
    let a = w.av();
    format!("{} {} {}.", j(det_m(n), n), v, a)
}
/// 4 data words: "Un gatto dorme piano verso la porta."
fn frame4(w: &mut Puller) -> String {
    let n = w.nm();
    let v = w.v();
    let a = w.av();
    let n2 = w.nf();
    format!("{} {} {} verso {}.", j(ind_m(n), n), v, a, j(det_f(n2), n2))
}
/// 5 data words: "La luce entra piano e scalda sempre."
fn frame5(w: &mut Puller) -> String {
    let n = w.nf();
    let v = w.v();
    let a = w.av();
    let v2 = w.v();
    let a2 = w.av();
    format!("{} {} {} e {} {}.", j(det_f(n), n), v, a, v2, a2)
}
/// 6 data words: "Il cane dorme piano mentre la luna brilla piano."
fn frame6(w: &mut Puller) -> String {
    let n = w.nm();
    let v = w.v();
    let a = w.av();
    let n2 = w.nf();
    let v2 = w.v();
    let a2 = w.av();
    format!(
        "{} {} {} mentre {} {} {}.",
        j(det_m(n), n),
        v,
        a,
        j(det_f(n2), n2),
        v2,
        a2
    )
}
/// 7 data words: "La luna splende piano e il cane dorme sempre nel bosco."
fn frame7a(w: &mut Puller) -> String {
    let n1 = w.nf();
    let v1 = w.v();
    let a1 = w.av();
    let n2 = w.nm();
    let v2 = w.v();
    let a2 = w.av();
    let n3 = w.nm();
    format!(
        "{} {} {} e {} {} {} {}.",
        j(det_f(n1), n1),
        v1,
        a1,
        j(det_m(n2), n2),
        v2,
        a2,
        j(nel_m(n3), n3)
    )
}
/// 7 data words (variant): "Il vento soffia forte e la pioggia cade piano nel campo."
fn frame7b(w: &mut Puller) -> String {
    let n1 = w.nm();
    let v1 = w.v();
    let a1 = w.av();
    let n2 = w.nf();
    let v2 = w.v();
    let a2 = w.av();
    let n3 = w.nm();
    format!(
        "{} {} {} e {} {} {} {}.",
        j(det_m(n1), n1),
        v1,
        a1,
        j(det_f(n2), n2),
        v2,
        a2,
        j(nel_m(n3), n3)
    )
}
/// 7 data words (dense): "La pioggia cade piano, scorre forte e bagna sempre."
fn frame7c(w: &mut Puller) -> String {
    let n = w.nf();
    let v1 = w.v();
    let a1 = w.av();
    let v2 = w.v();
    let a2 = w.av();
    let v3 = w.v();
    let a3 = w.av();
    format!(
        "{} {} {}, {} {} e {} {}.",
        j(det_f(n), n),
        v1,
        a1,
        v2,
        a2,
        v3,
        a3
    )
}

/// Encode bytes as a short Italian-looking text.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut w = Puller { it: data.iter() };
    let mut out = String::new();
    let mut rem = data.len();
    let mut pick = 0usize;
    while rem > 0 {
        let (s, used) = match rem.min(7) {
            1 => (frame1(&mut w), 1),
            2 => (frame2(&mut w), 2),
            3 => (frame3(&mut w), 3),
            4 => (frame4(&mut w), 4),
            5 => (frame5(&mut w), 5),
            6 => (frame6(&mut w), 6),
            _ => {
                pick += 1;
                match pick % 3 {
                    0 => (frame7a(&mut w), 7),
                    1 => (frame7b(&mut w), 7),
                    _ => (frame7c(&mut w), 7),
                }
            }
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&cap(&s));
        rem -= used;
    }
    out
}

/// Decode a sentences payload back to bytes. Fails cleanly on any token that
/// is neither a carrier nor a dictionary word.
pub fn decode(input: &str) -> Result<Vec<u8>, CodecError> {
    let map = word_map();
    let mut out = Vec::new();
    let mut saw_data = false;
    for tok in input
        .to_lowercase()
        .split(|c: char| !c.is_alphabetic())
        .filter(|t| !t.is_empty())
    {
        if CARRIERS.contains(&tok) {
            continue;
        }
        match map.get(tok) {
            Some(&b) => {
                saw_data = true;
                out.push(b);
            }
            None => return Err(CodecError::Malformed),
        }
    }
    if !saw_data {
        return Err(CodecError::Malformed);
    }
    Ok(out)
}

fn word_map() -> &'static HashMap<&'static str, u8> {
    static MAP: OnceLock<HashMap<&'static str, u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::with_capacity(1024);
        for list in [nm_list(), nf_list(), v_list(), av_list()] {
            for (i, &w) in list.iter().enumerate() {
                m.insert(w, i as u8);
            }
        }
        m
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn lists_are_256_and_unique() {
        for list in [nm_list(), nf_list(), v_list(), av_list()] {
            assert_eq!(list.len(), 256);
            let set: HashSet<_> = list.iter().collect();
            assert_eq!(set.len(), list.len(), "duplicate in list");
        }
        // no carrier/data collisions and no cross-class collisions
        let all: HashSet<_> = nm_list()
            .iter()
            .chain(nf_list())
            .chain(v_list())
            .chain(av_list())
            .collect();
        assert_eq!(all.len(), 1024, "word shared between classes");
        for &c in CARRIERS {
            assert!(!all.contains(&c), "carrier '{c}' collides with data word");
        }
    }

    #[test]
    fn roundtrip_various_lengths() {
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 13, 37, 64, 255] {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = encode(&d);
            assert_eq!(decode(&s).unwrap(), d, "len {n}: {s}");
        }
    }

    #[test]
    fn decode_tolerates_punctuation_and_case() {
        let d: Vec<u8> = (0..20).map(|i| (i * 13) as u8).collect();
        let mut s = encode(&d);
        s = s.to_uppercase();
        assert_eq!(decode(&s).unwrap(), d);
    }
}
