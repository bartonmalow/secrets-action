module.exports = {
  ignores: [
    'dist/**',
    'node_modules/**',
    'coverage/**',
    'lib/**',
    '*.min.js',
    'bundle.js',
    '**/vendor/**',
  ],
  rules: {
    semi: ['error', 'always'],
    quotes: ['error', 'single'],
  },
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
};
