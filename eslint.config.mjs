import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import vue from 'eslint-plugin-vue';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      'node_modules/**',
      'runtime/**',
      'test-results/**',
      'playwright-report/**',
    ],
  },
  js.configs.recommended,
  { files: ['scripts/**/*.mjs'], languageOptions: { globals: globals.node } },
  ...tseslint.configs.recommended,
  ...vue.configs['flat/recommended'],
  {
    files: ['apps/web/**/*.{ts,vue}'],
    languageOptions: { globals: globals.browser },
  },
  {
    files: ['**/*.vue'],
    languageOptions: { parserOptions: { parser: tseslint.parser, extraFileExtensions: ['.vue'] } },
    rules: { 'vue/multi-word-component-names': 'off' },
  },
  prettier,
);
