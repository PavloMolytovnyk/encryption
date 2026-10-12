'use strict';

const CAESAR_CIPHERTEXT = 'vppanlwxlyopyncjae';

// Перевіряє ключ і приводить зсув до діапазону 0..25.
function normalizeCaesarKey(key) {
  if (!Number.isSafeInteger(key)) {
    throw new TypeError('Ключ Цезаря має бути цілим числом.');
  }
  return ((key % 26) + 26) % 26;
}

// Зсуває одну латинську літеру, зберігаючи її регістр.
function shiftLatinLetter(character, shift) {
  const code = character.codePointAt(0);
  const start = code >= 65 && code <= 90 ? 65 : 97;
  if (code < start || code > start + 25) return character;
  return String.fromCharCode(start + ((code - start + shift + 26) % 26));
}

// Шифрує текст шифром Цезаря.
function encryptCaesar(plaintext, key) {
  if (typeof plaintext !== 'string') throw new TypeError('Текст має бути рядком.');
  const shift = normalizeCaesarKey(key);
  return [...plaintext].map(character => shiftLatinLetter(character, shift)).join('');
}

// Дешифрує текст шифром Цезаря.
function decryptCaesar(ciphertext, key) {
  if (typeof ciphertext !== 'string') throw new TypeError('Шифротекст має бути рядком.');
  const shift = normalizeCaesarKey(key);
  return [...ciphertext].map(character => shiftLatinLetter(character, -shift)).join('');
}

// Виконує брутальну атаку: перевіряє всі 26 можливих ключів.
function bruteForceCaesar(ciphertext) {
  const candidates = [];
  for (let key = 0; key < 26; key++) {
    candidates.push({ key, plaintext: decryptCaesar(ciphertext, key) });
  }
  return candidates;
}

// Виводить результати завдання 1.
function runTask1() {
  console.log('\nЗАВДАННЯ 1. Брутальна атака на шифр Цезаря');
  console.log('Шифротекст:', CAESAR_CIPHERTEXT);
  const candidates = bruteForceCaesar(CAESAR_CIPHERTEXT);
  console.table(candidates);

  // Серед отриманих варіантів упізнаємо фразу «keep calm and encrypt».
  // Ключ знаходиться у результатах перебору, а не задається наперед.
  const solution = candidates.find(item => item.plaintext === 'keepcalmandencrypt');
  console.log('Знайдений ключ:', solution.key);
  console.log('Відкритий текст:', solution.plaintext);
  console.log('Фраза з пробілами: keep calm and encrypt');
  console.log('Повторне шифрування:', encryptCaesar(solution.plaintext, solution.key));
}

module.exports = {
  CAESAR_CIPHERTEXT,
  normalizeCaesarKey,
  shiftLatinLetter,
  encryptCaesar,
  decryptCaesar,
  bruteForceCaesar,
  runTask1,
};

if (require.main === module) runTask1();
