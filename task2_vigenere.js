'use strict';

// Усі 33 літери українського алфавіту, включно з ґ, є, і та ї.
const UKRAINIAN_ALPHABET = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя';
const DEFAULT_SURNAME = 'Молитовник';
const VIGENERE_SAMPLE = 'криптографічнiметодизахистуінформації';

// Виправляє латинську i/I з прикладу на українську і/І.
// Нормалізація виконується окремо від шифрування та дешифрування.
function normalizeUkrainianText(text) {
  if (typeof text !== 'string') throw new TypeError('Текст має бути рядком.');
  return text.normalize('NFC').replace(/i/g, 'і').replace(/I/g, 'І');
}

// Перетворює літери прізвища на числові зсуви 0..32.
function prepareVigenereKey(key) {
  if (typeof key !== 'string') throw new TypeError('Ключ має бути рядком.');
  const letters = normalizeUkrainianText(key)
    .toLowerCase()
    .replace(/[\s'’ʼ-]/g, '');
  if (letters.length === 0) throw new Error('Ключ не може бути порожнім.');
  return [...letters].map(character => {
    const index = UKRAINIAN_ALPHABET.indexOf(character);
    if (index === -1) throw new Error('Ключ має містити українські літери.');
    return index;
  });
}

// Відновлює регістр зашифрованої або розшифрованої літери.
function restoreLetterCase(letter, originalCharacter) {
  return originalCharacter === originalCharacter.toUpperCase()
    ? letter.toUpperCase()
    : letter;
}

// Шифрує українські літери за формулою C = (P + K) mod 33.
function encryptVigenere(plaintext, key) {
  if (typeof plaintext !== 'string') throw new TypeError('Текст має бути рядком.');
  const shifts = prepareVigenereKey(key);
  let keyPosition = 0;
  let ciphertext = '';
  for (const character of plaintext) {
    const index = UKRAINIAN_ALPHABET.indexOf(character.toLowerCase());
    if (index === -1) {
      ciphertext += character;
      continue; // Пробіли та інші символи не зсувають позицію ключа.
    }
    const shift = shifts[keyPosition % shifts.length];
    const letter = UKRAINIAN_ALPHABET[(index + shift) % UKRAINIAN_ALPHABET.length];
    ciphertext += restoreLetterCase(letter, character);
    keyPosition++;
  }
  return ciphertext;
}

// Дешифрує українські літери за формулою P = (C - K + 33) mod 33.
function decryptVigenere(ciphertext, key) {
  if (typeof ciphertext !== 'string') throw new TypeError('Шифротекст має бути рядком.');
  const shifts = prepareVigenereKey(key);
  let keyPosition = 0;
  let plaintext = '';
  for (const character of ciphertext) {
    const index = UKRAINIAN_ALPHABET.indexOf(character.toLowerCase());
    if (index === -1) {
      plaintext += character;
      continue;
    }
    const shift = shifts[keyPosition % shifts.length];
    const letter = UKRAINIAN_ALPHABET[
      (index - shift + UKRAINIAN_ALPHABET.length) % UKRAINIAN_ALPHABET.length
    ];
    plaintext += restoreLetterCase(letter, character);
    keyPosition++;
  }
  return plaintext;
}

// Виводить результати завдання 2.
function runTask2(surname = DEFAULT_SURNAME) {
  const plaintext = normalizeUkrainianText(VIGENERE_SAMPLE);
  const ciphertext = encryptVigenere(plaintext, surname);
  const decrypted = decryptVigenere(ciphertext, surname);
  console.log('\nЗАВДАННЯ 2. Український шифр Віженера');
  console.log('Ключ-прізвище:', surname);
  console.log('Текст з умови:', VIGENERE_SAMPLE);
  console.log('Після заміни латинської i на українську і:', plaintext);
  console.log('Шифротекст:', ciphertext);
  console.log('Розшифрований текст:', decrypted);
  console.log('Перевірка:', decrypted === plaintext ? 'УСПІШНО' : 'ПОМИЛКА');
}

module.exports = {
  UKRAINIAN_ALPHABET,
  DEFAULT_SURNAME,
  VIGENERE_SAMPLE,
  normalizeUkrainianText,
  prepareVigenereKey,
  restoreLetterCase,
  encryptVigenere,
  decryptVigenere,
  runTask2,
};

if (require.main === module) runTask2(process.argv[2] ?? DEFAULT_SURNAME);
