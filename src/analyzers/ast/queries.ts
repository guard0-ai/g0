import type { SyntaxNode, Tree } from './parser.js';

export function findNodes(
  tree: Tree | { rootNode: SyntaxNode },
  predicate: (node: SyntaxNode) => boolean,
): SyntaxNode[] {
  const results: SyntaxNode[] = [];
  function traverse(node: SyntaxNode): void {
    if (predicate(node)) results.push(node);
    for (const child of node.children) {
      traverse(child);
    }
  }
  traverse(tree.rootNode);
  return results;
}

export function findFunctionCalls(
  tree: Tree,
  functionName: string | RegExp,
): SyntaxNode[] {
  const callTypes = ['call_expression', 'call'];

  return findNodes(tree, (node) => {
    if (!callTypes.includes(node.type)) return false;

    const callee = node.childForFieldName('function');
    if (!callee) return false;

    const calleeText = callee.text;
    if (!calleeText) return false;

    if (typeof functionName === 'string') {
      return calleeText === functionName || calleeText.endsWith(`.${functionName}`);
    }
    return functionName.test(calleeText);
  });
}

export function findImports(tree: Tree): SyntaxNode[] {
  const importTypes = [
    'import_statement',
    'import_from_statement',
    'import_declaration',
  ];

  return findNodes(tree, (node) =>
    importTypes.includes(node.type) ||
    (node.type === 'call_expression' &&
      node.childForFieldName('function')?.text === 'require'),
  );
}

export function findAssignments(
  tree: Tree | { rootNode: SyntaxNode },
  variableName?: string | RegExp,
): SyntaxNode[] {
  const assignmentTypes = [
    'variable_declarator',
    'assignment_expression',
    'assignment',
    'augmented_assignment',
  ];

  return findNodes(tree, (node) => {
    if (!assignmentTypes.includes(node.type)) return false;

    let nameText: string | null = null;
    if (node.type === 'variable_declarator') {
      nameText = node.childForFieldName('name')?.text ?? null;
    } else {
      nameText = node.childForFieldName('left')?.text ?? null;
    }

    if (!variableName) return nameText !== null;
    if (!nameText) return false;

    if (typeof variableName === 'string') return nameText === variableName;
    return variableName.test(nameText);
  });
}

export function getCallArgument(
  callNode: SyntaxNode,
  index: number,
): SyntaxNode | null {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;

  const positionalArgs = args.children.filter(
    (c) =>
      c.type !== '(' &&
      c.type !== ')' &&
      c.type !== ',' &&
      c.type !== 'keyword_argument',
  );

  return positionalArgs[index] ?? null;
}

export function getKeywordArgument(
  callNode: SyntaxNode,
  name: string,
): SyntaxNode | null {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;

  for (const child of args.children) {
    if (child.type === 'keyword_argument') {
      const nameNode = child.childForFieldName('name');
      if (nameNode && nameNode.text === name) {
        return child.childForFieldName('value');
      }
    }
  }
  return null;
}

export function extractStringValue(node: SyntaxNode): string | null {
  if (node.type === 'string' || node.type === 'string_literal') {
    const text = node.text;
    if (text.startsWith('"""') || text.startsWith("'''")) return text.slice(3, -3);
    if (text.startsWith('f"""') || text.startsWith("f'''")) return text.slice(4, -3);
    if (text.startsWith('f"') || text.startsWith("f'")) return text.slice(2, -1);
    if (text.startsWith('"') || text.startsWith("'")) return text.slice(1, -1);
    if (text.startsWith('`')) return text.slice(1, -1);
    return text;
  }
  if (node.type === 'template_string') {
    return node.children
      .filter((c) => c.type === 'string_fragment')
      .map((c) => c.text)
      .join('');
  }
  if (node.type === 'concatenated_string') {
    return node.children.map((c) => extractStringValue(c)).filter(Boolean).join('');
  }
  if (node.type === 'binary_expression') {
    const op = node.childForFieldName('operator');
    if (op?.text === '+') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left && right) {
        const l = extractStringValue(left);
        const r = extractStringValue(right);
        if (l && r) return l + r;
      }
    }
  }
  return null;
}

export function isInDangerousContext(tree: Tree, variableName: string): boolean {
  const usages = findNodes(
    tree,
    (node) => node.type === 'identifier' && node.text === variableName,
  );

  for (const usage of usages) {
    if (usage.parent?.type === 'binary_expression' || usage.parent?.type === 'binary_operator') {
      const operator = usage.parent.childForFieldName('operator') ??
        usage.parent.children.find(c => c.text === '+');
      if (operator?.text === '+') return true;
    }
    if (usage.parent?.type === 'template_substitution') return true;
    if (usage.parent?.type === 'interpolation') return true;

    let current = usage.parent;
    while (current) {
      if (current.type === 'call_expression' || current.type === 'call') {
        const callee = current.childForFieldName('function');
        if (callee && /^(eval|exec|compile)$/.test(callee.text)) return true;
        break;
      }
      if (current.type === 'arguments' || current.type === 'argument_list') {
        current = current.parent;
        continue;
      }
      current = current.parent;
    }
  }
  return false;
}

export function findAllStrings(tree: Tree | { rootNode: SyntaxNode }): SyntaxNode[] {
  return findNodes(tree, (node) =>
    node.type === 'string' ||
    node.type === 'string_literal' ||
    node.type === 'template_string' ||
    node.type === 'concatenated_string',
  );
}

export function findTryCatchBlocks(tree: Tree | { rootNode: SyntaxNode }): SyntaxNode[] {
  return findNodes(tree, (node) =>
    node.type === 'try_statement' ||
    node.type === 'try_except_statement' ||   // Python
    node.type === 'except_clause' ||
    node.type === 'catch_clause',
  );
}

export function findLoopConstructs(tree: Tree | { rootNode: SyntaxNode }): SyntaxNode[] {
  return findNodes(tree, (node) =>
    node.type === 'while_statement' ||
    node.type === 'for_statement' ||
    node.type === 'for_in_statement' ||
    node.type === 'do_statement',
  );
}

/**
 * Checks whether a match at `matchIndex` sits inside a block comment.
 * Supports JS/TS `/* ... *​/` and Python `"""..."""` / `'''...'''`.
 */
export function isInBlockComment(content: string, matchIndex: number, language: string): boolean {
  if (language === 'go') {
    // Go uses /* ... */ block comments (same as JS/TS) — fall through below
  } else if (language === 'python') {
    // Check triple-quote block comments (""" and ''')
    for (const delim of ['"""', "'''"]) {
      let pos = 0;
      while (pos < content.length) {
        const open = content.indexOf(delim, pos);
        if (open === -1) break;
        const close = content.indexOf(delim, open + 3);
        if (close === -1) break;
        if (matchIndex > open && matchIndex < close + 3) return true;
        pos = close + 3;
      }
    }
    return false;
  }
  // JS/TS: /* ... */
  let pos = 0;
  while (pos < content.length) {
    const open = content.indexOf('/*', pos);
    if (open === -1) break;
    const close = content.indexOf('*/', open + 2);
    if (close === -1) {
      // Unclosed block comment — everything after open is commented
      return matchIndex > open;
    }
    if (matchIndex > open && matchIndex < close + 2) return true;
    pos = close + 2;
  }
  return false;
}

/**
 * Checks whether a match at `matchIndex` sits inside a string literal
 * that is assigned to a documentation/example variable or is a raw string constant.
 * This catches SQL examples in docstrings, example URLs, etc.
 */
export function isInStringLiteral(content: string, matchIndex: number, language: string): boolean {
  const lineStart = content.lastIndexOf('\n', matchIndex - 1) + 1;
  const lineEnd = content.indexOf('\n', matchIndex);
  const line = content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd);

  // Check if the match is inside a simple string assignment that looks like docs/examples
  // e.g. `example = "SELECT * FROM users"` or `const doc = "..."`
  const docAssign = /^\s*(?:const|let|var|val)?\s*(?:example|doc|description|help|usage|comment|readme|template|placeholder|sample|demo)\w*\s*[=:]/i;
  if (docAssign.test(line)) return true;

  // Check if match is within a Java/Go annotation or decorator
  if (language === 'java' || language === 'go') {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('@') || trimmed.startsWith('//go:')) return true;
  }

  return false;
}

export function isCommentLine(content: string, matchIndex: number, language: string): boolean {
  // Check block comments first
  if (isInBlockComment(content, matchIndex, language)) return true;
  // Check documentation string literals
  if (isInStringLiteral(content, matchIndex, language)) return true;
  const lineStart = content.lastIndexOf('\n', matchIndex - 1) + 1;
  const lineEnd = content.indexOf('\n', matchIndex);
  const line = content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd).trimStart();
  if (language === 'python') return line.startsWith('#');
  // Java, Go, JS, TS all use // for line comments
  return line.startsWith('//');
}

export function canDataFlow(
  tree: Tree,
  sourceVar: string,
  sinkPattern: RegExp,
): boolean {
  const taintedVars = new Set<string>([sourceVar]);

  const assignments = findAssignments(tree);
  for (const assignment of assignments) {
    const leftNode =
      assignment.type === 'variable_declarator'
        ? assignment.childForFieldName('name')
        : assignment.childForFieldName('left');
    const rightNode =
      assignment.type === 'variable_declarator'
        ? assignment.childForFieldName('value')
        : assignment.childForFieldName('right');

    if (!leftNode || !rightNode) continue;

    const containsTainted =
      findNodes({ rootNode: rightNode } as Tree, (n) =>
        n.type === 'identifier' && taintedVars.has(n.text),
      ).length > 0;

    if (containsTainted) taintedVars.add(leftNode.text);
  }

  const calls = findFunctionCalls(tree, sinkPattern);
  for (const call of calls) {
    const args = call.childForFieldName('arguments');
    if (!args) continue;

    for (const arg of args.children) {
      if (arg.type === 'identifier' && taintedVars.has(arg.text)) return true;
      const identifiers = findNodes({ rootNode: arg } as Tree, (n) => n.type === 'identifier');
      for (const id of identifiers) {
        if (taintedVars.has(id.text)) return true;
      }
    }
  }
  return false;
}
