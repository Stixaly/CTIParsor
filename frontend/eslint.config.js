// ESLint flat config: the TypeScript-aware recommended rules, the two classic
// React Hooks rules (https://react.dev/reference/eslint-plugin-react-hooks),
// and the formatting rules this codebase already follows.  `npm run lint`
// runs it; `npm run check` runs it with tsc and Vitest, the same steps as the
// CI frontend job.
//
// The plugin's `recommended` preset also carries the React Compiler
// diagnostics (set-state-in-effect, immutability, refs, ...).  This app does
// not use the compiler, and those rules flag 36 places that work as written;
// adopting them is a refactor of its own, not a lint switch.
//
// Formatting is checked, not rewritten: Prettier would re-wrap 73 of the 82
// source files and undo the hand-aligned columns the code relies on for
// readability.  The rules below hold the conventions the code already has
// (single quotes, no semicolons, clean whitespace) with zero rewrites.
import js from '@eslint/js'
import stylistic from '@stylistic/eslint-plugin'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'public'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      // A leading underscore marks a parameter kept for its signature.
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_',
      }],
      // `cond ? a() : b()` as a statement is this codebase's idiom for handlers.
      '@typescript-eslint/no-unused-expressions': ['error', {
        allowTernary: true, allowShortCircuit: true,
      }],
      // `catch {}` around localStorage: it throws in some private windows.
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  {
    files: ['**/*.{ts,tsx,js}'],
    plugins: { '@stylistic': stylistic },
    rules: {
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true, allowTemplateLiterals: 'always' }],
      '@stylistic/jsx-quotes': ['error', 'prefer-double'],
      '@stylistic/semi': ['error', 'never'],
      '@stylistic/no-trailing-spaces': 'error',
      '@stylistic/eol-last': 'error',
      '@stylistic/no-tabs': 'error',
      '@stylistic/no-mixed-spaces-and-tabs': 'error',
      '@stylistic/no-multiple-empty-lines': ['error', { max: 2, maxEOF: 0 }],
      '@stylistic/comma-spacing': 'error',
      '@stylistic/keyword-spacing': 'error',
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/arrow-spacing': 'error',
    },
  },
  {
    files: ['*.{js,ts}'],
    languageOptions: { globals: globals.node },
  },
)
