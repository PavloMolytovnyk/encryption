'use strict';

const { runTask1 } = require('./task1_caesar');
const { DEFAULT_SURNAME, runTask2 } = require('./task2_vigenere');
const { runTask3 } = require('./task3_rsa_number');
const { RSA_TEXT_SAMPLE, runTask4 } = require('./task4_rsa_text');

// Запускає лише вибране завдання.
function runSelectedTask(task, parameter) {
  switch (task) {
    case '1': return runTask1();
    case '2': return runTask2(parameter ?? DEFAULT_SURNAME);
    case '3': return runTask3();
    case '4': return runTask4(parameter ?? RSA_TEXT_SAMPLE);
    case 'all':
      runTask1();
      runTask2(parameter ?? DEFAULT_SURNAME);
      runTask3();
      return runTask4();
    default: throw new Error('Завдання: 1, 2, 3, 4 або all. Приклад: node lab5.js all "Молитовник"');
  }
}

// Обробляє аргументи командного рядка і виводить помилки запуску.
function main() {
  const [task = 'all', parameter] = process.argv.slice(2);
  try {
    runSelectedTask(task, parameter);
  } catch (error) {
    console.error('Помилка:', error.message);
    process.exitCode = 1;
  }
}

module.exports = { runSelectedTask, main };
if (require.main === module) main();
