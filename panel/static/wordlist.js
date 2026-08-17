// Recovery-secret wordlist. 256 words, 8 bits each, so a 256-bit secret is 32 words.
//
// WHY NOT BIP-39. BIP-39's 2048-word list gives 11 bits per word and would render 256
// bits in 24 words. It is the obvious choice and it was rejected here for one reason:
// this list has to be reproduced correctly, and a list nobody can verify by eye is a
// list with a typo in it. A single wrong word makes a printed recovery secret
// unreadable — and per HR-4.5 that secret is one of only three ways into the audit key,
// with no fourth copy anywhere. 256 words is short enough to audit by reading.
//
// PROPERTIES, all of which the tests check:
//   - exactly 256 entries, so each word is exactly one byte and no checksum arithmetic
//     is needed (no bit-packing bugs, which is the other place BIP-39 implementations
//     go wrong)
//   - unique at four characters, so a handwritten word is recoverable if the tail is
//     smudged
//   - lowercase a-z only, 3 to 7 characters, no plurals of other entries, no
//     homophones, nothing that looks like another entry in shaky handwriting
//
// STABILITY: this list is append-only-never. Changing or reordering ANY entry silently
// invalidates every recovery secret ever printed. Treat a change here as key rotation.
'use strict';

const WORDLIST = [
  'able', 'acid', 'acorn', 'actor', 'adapt', 'admit', 'adopt', 'agent',
  'agree', 'ahead', 'alarm', 'album', 'alert', 'alien', 'alive', 'alley',
  'alloy', 'alone', 'amber', 'amble', 'amino', 'ample', 'anchor', 'angle',
  'ankle', 'apart', 'apex', 'apple', 'april', 'apron', 'arbor', 'arch',
  'arena', 'argue', 'arid', 'armor', 'array', 'arrow', 'ash', 'aside',
  'asset', 'atlas', 'atom', 'audio', 'aura', 'aunt', 'avoid', 'awake',
  'award', 'axis', 'bacon', 'badge', 'bagel', 'baker', 'balm', 'banjo',
  'barn', 'basil', 'baton', 'batch', 'beach', 'beam', 'bean', 'bench',
  'berry', 'bike', 'bingo', 'birch', 'bison', 'blade', 'blaze', 'blend',
  'bliss', 'block', 'blue', 'blush', 'board', 'bolt', 'bonus', 'boost',
  'bound', 'brave', 'bread', 'brick', 'brisk', 'broom', 'brush', 'bugle',
  'bulb', 'bunk', 'buyer', 'cabin', 'cable', 'cache', 'cadet', 'camel',
  'candy', 'canoe', 'canvas', 'canyon', 'cargo', 'carve', 'cedar', 'chalk',
  'charm', 'chess', 'chief', 'chime', 'churn', 'cider', 'cigar', 'cinch',
  'civic', 'claim', 'clay', 'clerk', 'cliff', 'cloak', 'clock', 'cloud',
  'clump', 'coach', 'coast', 'cobra', 'cocoa', 'coin', 'comet', 'coral',
  'couch', 'cover', 'crane', 'crate', 'creek', 'crisp', 'crown', 'cube',
  'cumin', 'curve', 'cycle', 'daisy', 'dance', 'dandy', 'dawn', 'debut',
  'decoy', 'deity', 'delta', 'demo', 'denim', 'depot', 'derby', 'desk',
  'diary', 'diner', 'ditch', 'dizzy', 'dock', 'dodge', 'dolly', 'donor',
  'dough', 'dozen', 'draft', 'drama', 'dream', 'drift', 'drum', 'dryer',
  'duck', 'duet', 'dune', 'dusk', 'eagle', 'early', 'earth', 'easel',
  'echo', 'edge', 'eight', 'elbow', 'elder', 'elf', 'elope', 'ember',
  'emit', 'empty', 'enact', 'ended', 'enemy', 'enjoy', 'entry', 'envoy',
  'epoch', 'equal', 'error', 'essay', 'ether', 'event', 'evict', 'exact',
  'exile', 'exit', 'extra', 'fable', 'fancy', 'fang', 'farm', 'fault',
  'favor', 'feast', 'fence', 'fern', 'ferry', 'fetch', 'fever', 'fiber',
  'field', 'fifth', 'film', 'final', 'finch', 'fiscal', 'flag', 'flame',
  'flask', 'fleet', 'flint', 'float', 'flock', 'flour', 'fluid', 'flute',
  'foam', 'focal', 'foggy', 'foil', 'folk', 'forge', 'forum', 'fossil',
  'found', 'fox', 'frame', 'fresh', 'frost', 'fruit', 'fudge', 'fuel',
  'fully', 'fungus', 'gable', 'gadget', 'gain', 'galaxy', 'gamma', 'garlic',
];

if (WORDLIST.length !== 256) {
  // Loud on load, not silent at 3am. A short list would silently truncate entropy.
  throw new Error(`wordlist must be exactly 256 entries, found ${WORDLIST.length}`);
}

const INDEX = new Map(WORDLIST.map((w, i) => [w, i]));
if (INDEX.size !== 256) {
  throw new Error('wordlist contains a duplicate');
}

/** 32 bytes -> 32 words. One byte per word, no bit packing, nothing to get wrong. */
function bytesToWords(bytes) {
  return Array.from(bytes, (b) => WORDLIST[b]).join(' ');
}

/** 32 words -> 32 bytes. Throws on any unknown word rather than guessing. */
function wordsToBytes(phrase) {
  const words = phrase.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const out = new Uint8Array(words.length);
  words.forEach((w, i) => {
    const v = INDEX.get(w);
    if (v === undefined) throw new Error(`not in wordlist: ${w}`);
    out[i] = v;
  });
  return out;
}

window.tetherWordlistHas = (w) => INDEX.has(w);
window.tetherWordlist = { bytesToWords, wordsToBytes, size: WORDLIST.length };
