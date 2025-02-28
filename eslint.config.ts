import * as tsParser from '@typescript-eslint/parser'
import js from "@eslint/js"
import eslintPluginPrettier from 'eslint-plugin-prettier'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { includeIgnoreFile } from '@eslint/compat'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const gitignorePath = path.resolve(__dirname, '.gitignore')

export default [
  js.configs.recommended,
  eslintPluginPrettier.configs?.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: 'tsconfig.json',
      },
    }
  },
  includeIgnoreFile(gitignorePath),
]
