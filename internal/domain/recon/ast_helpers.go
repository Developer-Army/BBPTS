package recon

import "github.com/dop251/goja/ast"

func stringLiteralValue(lit *ast.StringLiteral) string {
	if lit == nil {
		return ""
	}
	return lit.Value.String()
}

func propertyKeyName(key ast.Expression) string {
	switch k := key.(type) {
	case *ast.Identifier:
		return k.Name.String()
	case *ast.StringLiteral:
		return stringLiteralValue(k)
	default:
		return ""
	}
}

func walkJSAST(node ast.Node, visitor func(ast.Node)) {
	if node == nil {
		return
	}
	visitor(node)

	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			walkJSAST(stmt, visitor)
		}
		for _, decl := range n.DeclarationList {
			walkJSAST(decl, visitor)
		}
	case *ast.BlockStatement:
		for _, stmt := range n.List {
			walkJSAST(stmt, visitor)
		}
	case *ast.ExpressionStatement:
		walkJSAST(n.Expression, visitor)
	case *ast.VariableStatement:
		for _, binding := range n.List {
			walkJSAST(binding, visitor)
		}
	case *ast.LexicalDeclaration:
		for _, binding := range n.List {
			walkJSAST(binding, visitor)
		}
	case *ast.VariableDeclaration:
		for _, binding := range n.List {
			walkJSAST(binding, visitor)
		}
	case *ast.Binding:
		walkJSAST(n.Target, visitor)
		walkJSAST(n.Initializer, visitor)
	case *ast.FunctionDeclaration:
		walkJSAST(n.Function, visitor)
	case *ast.FunctionLiteral:
		for _, decl := range n.DeclarationList {
			walkJSAST(decl, visitor)
		}
		walkJSAST(n.Body, visitor)
	case *ast.ArrowFunctionLiteral:
		walkJSAST(n.Body, visitor)
	case *ast.ExpressionBody:
		walkJSAST(n.Expression, visitor)
	case *ast.ClassDeclaration:
		walkJSAST(n.Class, visitor)
	case *ast.ClassLiteral:
		walkJSAST(n.SuperClass, visitor)
		for _, elem := range n.Body {
			walkJSAST(elem, visitor)
		}
	case *ast.FieldDefinition:
		walkJSAST(n.Key, visitor)
		walkJSAST(n.Initializer, visitor)
	case *ast.MethodDefinition:
		walkJSAST(n.Key, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.ClassStaticBlock:
		walkJSAST(n.Block, visitor)
	case *ast.ReturnStatement:
		walkJSAST(n.Argument, visitor)
	case *ast.ThrowStatement:
		walkJSAST(n.Argument, visitor)
	case *ast.IfStatement:
		walkJSAST(n.Test, visitor)
		walkJSAST(n.Consequent, visitor)
		walkJSAST(n.Alternate, visitor)
	case *ast.ForStatement:
		walkJSAST(n.Initializer, visitor)
		walkJSAST(n.Test, visitor)
		walkJSAST(n.Update, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.ForLoopInitializerExpression:
		walkJSAST(n.Expression, visitor)
	case *ast.ForLoopInitializerVarDeclList:
		for _, binding := range n.List {
			walkJSAST(binding, visitor)
		}
	case *ast.ForLoopInitializerLexicalDecl:
		walkJSAST(&n.LexicalDeclaration, visitor)
	case *ast.ForInStatement:
		walkJSAST(n.Into, visitor)
		walkJSAST(n.Source, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.ForOfStatement:
		walkJSAST(n.Into, visitor)
		walkJSAST(n.Source, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.ForIntoVar:
		walkJSAST(n.Binding, visitor)
	case *ast.ForDeclaration:
		walkJSAST(n.Target, visitor)
	case *ast.ForIntoExpression:
		walkJSAST(n.Expression, visitor)
	case *ast.WhileStatement:
		walkJSAST(n.Test, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.DoWhileStatement:
		walkJSAST(n.Body, visitor)
		walkJSAST(n.Test, visitor)
	case *ast.SwitchStatement:
		walkJSAST(n.Discriminant, visitor)
		for _, cs := range n.Body {
			walkJSAST(cs, visitor)
		}
	case *ast.CaseStatement:
		walkJSAST(n.Test, visitor)
		for _, stmt := range n.Consequent {
			walkJSAST(stmt, visitor)
		}
	case *ast.TryStatement:
		walkJSAST(n.Body, visitor)
		walkJSAST(n.Catch, visitor)
		walkJSAST(n.Finally, visitor)
	case *ast.CatchStatement:
		walkJSAST(n.Parameter, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.LabelledStatement:
		walkJSAST(n.Statement, visitor)
	case *ast.WithStatement:
		walkJSAST(n.Object, visitor)
		walkJSAST(n.Body, visitor)
	case *ast.ArrayLiteral:
		for _, expr := range n.Value {
			walkJSAST(expr, visitor)
		}
	case *ast.ArrayPattern:
		for _, expr := range n.Elements {
			walkJSAST(expr, visitor)
		}
		walkJSAST(n.Rest, visitor)
	case *ast.ObjectLiteral:
		for _, prop := range n.Value {
			walkJSAST(prop, visitor)
		}
	case *ast.ObjectPattern:
		for _, prop := range n.Properties {
			walkJSAST(prop, visitor)
		}
		walkJSAST(n.Rest, visitor)
	case *ast.PropertyKeyed:
		walkJSAST(n.Key, visitor)
		walkJSAST(n.Value, visitor)
	case *ast.PropertyShort:
		walkJSAST(n.Initializer, visitor)
	case *ast.SpreadElement:
		walkJSAST(n.Expression, visitor)
	case *ast.AssignExpression:
		walkJSAST(n.Left, visitor)
		walkJSAST(n.Right, visitor)
	case *ast.BinaryExpression:
		walkJSAST(n.Left, visitor)
		walkJSAST(n.Right, visitor)
	case *ast.BracketExpression:
		walkJSAST(n.Left, visitor)
		walkJSAST(n.Member, visitor)
	case *ast.CallExpression:
		walkJSAST(n.Callee, visitor)
		for _, arg := range n.ArgumentList {
			walkJSAST(arg, visitor)
		}
	case *ast.ConditionalExpression:
		walkJSAST(n.Test, visitor)
		walkJSAST(n.Consequent, visitor)
		walkJSAST(n.Alternate, visitor)
	case *ast.DotExpression:
		walkJSAST(n.Left, visitor)
	case *ast.PrivateDotExpression:
		walkJSAST(n.Left, visitor)
	case *ast.NewExpression:
		walkJSAST(n.Callee, visitor)
		for _, arg := range n.ArgumentList {
			walkJSAST(arg, visitor)
		}
	case *ast.SequenceExpression:
		for _, expr := range n.Sequence {
			walkJSAST(expr, visitor)
		}
	case *ast.TemplateLiteral:
		walkJSAST(n.Tag, visitor)
		for _, expr := range n.Expressions {
			walkJSAST(expr, visitor)
		}
	case *ast.UnaryExpression:
		walkJSAST(n.Operand, visitor)
	case *ast.YieldExpression:
		walkJSAST(n.Argument, visitor)
	case *ast.AwaitExpression:
		walkJSAST(n.Argument, visitor)
	}
}
