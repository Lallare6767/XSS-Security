# Contributing to XSS Guardian

Thank you for your interest in contributing to XSS Guardian! This document provides guidelines for contributing to the project.

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on what's best for the security community
- Show empathy towards other community members
- Accept constructive criticism gracefully
- Use welcoming and inclusive language

### Unacceptable Behavior

- Harassment, trolling, or discriminatory comments
- Publishing others' private information
- Promoting illegal activities or unauthorized testing
- Any conduct that would be inappropriate in a professional setting

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**Good bug reports include:**
- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Screenshots (if applicable)
- Your environment (browser, OS, XSS Guardian version)
- Sample code or test case

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- Clear, descriptive title
- Detailed description of the proposed functionality
- Why this enhancement would be useful
- Example use cases

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** if applicable
4. **Update documentation** to reflect your changes
5. **Ensure the build passes**: `npm run build`
6. **Submit a pull request** with a clear description

#### PR Guidelines

- One feature/fix per PR
- Write clear, descriptive commit messages
- Keep PRs focused and reasonably sized
- Link related issues
- Update CHANGELOG.md if applicable

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/xss-guardian.git
cd xss-guardian

# Install dependencies
npm install

# Run development build with watch
npm run watch

# Build for production
npm run build

# Run tests
npm test

# Lint code
npm run lint
```

## Coding Standards

### TypeScript Style Guide

- Use TypeScript strict mode
- Prefer interfaces over type aliases for object types
- Use meaningful variable and function names
- Add JSDoc comments for public APIs
- Keep functions small and focused
- Use async/await over raw promises

### Code Examples

**Good:**
```typescript
/**
 * Scan element for XSS vulnerabilities
 * @param element - DOM element to scan
 * @param options - Scan options
 * @returns Array of vulnerabilities found
 */
async function scanElement(
  element: Element,
  options: ScanOptions
): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  // Implementation...
  return vulnerabilities;
}
```

**Avoid:**
```typescript
// Bad: unclear function name, no types, no documentation
function scan(e, opts) {
  let v = [];
  // ...
  return v;
}
```

### File Organization

- One class/module per file
- Group related functionality
- Use barrel exports (index.ts) for public APIs
- Keep files under 500 lines when possible

### Naming Conventions

- **Classes**: PascalCase (`DOMAnalyzer`, `XSSGuardian`)
- **Functions**: camelCase (`scanElement`, `detectFramework`)
- **Constants**: UPPER_SNAKE_CASE (`DOM_SINKS`, `EVENT_HANDLERS`)
- **Interfaces**: PascalCase with 'I' prefix optional (`Vulnerability`, `ScanOptions`)
- **Files**: kebab-case (`dom-analyzer.ts`, `framework-detector.ts`)

## Testing

### Writing Tests

- Write tests for new features
- Update tests for bug fixes
- Aim for high code coverage
- Test edge cases

### Test Structure

```typescript
describe('DOMAnalyzer', () => {
  describe('scan', () => {
    it('should detect innerHTML vulnerabilities', () => {
      // Arrange
      const analyzer = new DOMAnalyzer();

      // Act
      const result = analyzer.scan();

      // Assert
      expect(result).toContainVulnerability('innerHTML');
    });
  });
});
```

## Security Contributions

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email security@example.com
2. Include detailed description
3. Provide proof-of-concept if possible
4. Allow reasonable time for response

### Adding New Payloads

When contributing XSS payloads:

1. **Ensure they're novel** - don't duplicate existing payloads
2. **Document the technique** - explain how/why it works
3. **Specify context** - where the payload is effective
4. **Include bypass info** - what filters/WAFs it bypasses
5. **Test thoroughly** - verify it works as expected

Example:
```typescript
{
  payload: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
  contexts: ['html'],
  description: 'SVG animate tag with onbegin event',
  bypassTechnique: 'Event handler in SVG context',
}
```

### Framework Analyzers

When adding framework-specific analyzers:

1. Extend `FrameworkDetector` interface
2. Implement all required methods
3. Add framework to `FRAMEWORK_PATTERNS`
4. Document framework-specific sinks/sources
5. Include detection tests

## Documentation

### Code Comments

- Use JSDoc for public APIs
- Explain *why*, not *what* for complex logic
- Keep comments up-to-date with code changes

### README Updates

- Keep examples working and relevant
- Update feature list when adding functionality
- Maintain accurate installation instructions

### CHANGELOG

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [1.2.0] - 2024-01-15

### Added
- New Alpine.js framework analyzer
- Support for Shadow DOM scanning

### Fixed
- Bug in mutation testing with nested iframes

### Changed
- Improved performance of DOM traversal
```

## Adding New Features

### Checklist

- [ ] Feature implemented in TypeScript
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] Examples added (if applicable)
- [ ] CHANGELOG updated
- [ ] No breaking changes (or clearly documented)
- [ ] Code follows style guide
- [ ] Build succeeds without warnings

## Questions?

- Open a GitHub issue for general questions
- Join our Discord community: [link]
- Email: contributors@example.com

## Recognition

Contributors will be:
- Listed in AUTHORS.md
- Mentioned in release notes
- Given credit in documentation

Thank you for helping make XSS Guardian better! 🛡️
