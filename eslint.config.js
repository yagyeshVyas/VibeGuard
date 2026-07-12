'use strict';

module.exports = [
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        setInterval: 'readonly',
        clearTimeout: 'readonly',
        clearInterval: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-prototype-builtins': 'warn',
      'no-control-regex': 'off',
      'no-useless-escape': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'prefer-const': 'warn',
      'no-var': 'warn',
      eqeqeq: ['warn', 'smart'],
      'no-eval': 'off',
      'no-new-func': 'off',
    },
  },
  {
    ignores: ['node_modules/', 'test-project/', 'coverage/', 'dist/', 'website/'],
  },
];
