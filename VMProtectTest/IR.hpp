#pragma once

namespace IR
{
	enum ir_size : triton::uint32
	{
		ir_size_b = 1,
		ir_size_w = 2,
		ir_size_d = 4,
		ir_size_q = 8
	};

	enum ir_segment
	{
		ir_segment_regular = triton::arch::ID_REG_INVALID,	// ds?
		ir_segment_scratch,
		ir_segment_cs = triton::arch::ID_REG_X86_CS,
		ir_segment_ds = triton::arch::ID_REG_X86_DS,
		ir_segment_es = triton::arch::ID_REG_X86_ES,
		ir_segment_fs = triton::arch::ID_REG_X86_FS,
		ir_segment_gs = triton::arch::ID_REG_X86_GS,
		ir_segment_ss = triton::arch::ID_REG_X86_SS,
	};

	enum expression_type
	{
		expr_register,
		expr_memory,
		expr_variable,
		expr_immediate,
		expr_deref,
		expr_unary_operation,
		expr_binary_operation
	};

	enum statement_type
	{
		ir_statement_assign,
		ir_statement_push,
		ir_statement_pop,
		ir_statement_ret,

		// special
		ir_statement_rdtsc,
		ir_statement_cpuid
	};

	enum binary_operation_type
	{
		binary_op_invalid = -1,
		binary_op_add,
		binary_op_sub,
		binary_op_shl,
		binary_op_shr,
		binary_op_rcr,
		binary_op_rcl,
		binary_op_rol,
		binary_op_ror,
		binary_op_and,
		binary_op_or,
		binary_op_xor,
		binary_op_cmp,
		binary_op_test
	};

	// Expression
	class Immediate;
	class Expression
	{
		expression_type m_type;

	protected:
		Expression(expression_type type) : m_type(type) {}
		virtual ~Expression() {}

	public:
		expression_type get_type() const
		{
			return this->m_type;
		}

	public:
		virtual void to_string(std::ostream& stream) const = 0;
	};
	std::ostream& operator<<(std::ostream& stream, const Expression& expr);
	std::ostream& operator<<(std::ostream& stream, const Expression* expr);
	extern std::shared_ptr<Expression> simplify_expression(const std::shared_ptr<Expression> &expression);


	// Register
	class Register : public Expression
	{
	public:
		// vm
		Register(triton::uint64 offset);

		// x86register
		Register(const triton::arch::Register &triton_register);

		virtual void to_string(std::ostream& stream) const override;

		std::string get_name() const;
		triton::uint64 get_offset() const;

	private:
		std::string m_name;
		triton::uint64 m_offset;
		triton::arch::Register m_register;
	};


	// Memory
	class Memory : public Expression
	{
	public:
		Memory(const std::shared_ptr<Expression> &expr, ir_segment segment, ir_size size);

		virtual void to_string(std::ostream& stream) const override;

		std::shared_ptr<Expression> get_expression() const;

	private:
		ir_size m_size;
		ir_segment m_segment;
		std::shared_ptr<Expression> m_expr;
	};


	// Variable
	class Variable : public Expression
	{
	public:
		Variable(ir_size size);
		Variable(const std::string &name, ir_size size);

		virtual void to_string(std::ostream& stream) const override;

		std::string get_name() const;

		static std::shared_ptr<Variable> create_variable(triton::uint32 size);

	private:
		static int s_index;
		std::string m_name;
		ir_size m_size;
	};


	// Immediate
	class Immediate : public Expression
	{
	public:
		Immediate(triton::uint64 immediate);

		virtual void to_string(std::ostream& stream) const override;

		triton::uint64 get_value() const { return this->m_immediate; }

	private:
		triton::uint64 m_immediate;
	};


	// Dereference (y = Deref(x))
	class Dereference : public Expression
	{
	public:
		Dereference(const std::shared_ptr<Expression> &expr, ir_segment segment, ir_size size);

		virtual void to_string(std::ostream& stream) const override;

		std::shared_ptr<Expression> get_expression() const;
		void set_expression(const std::shared_ptr<Expression> &expr);

	private:
		ir_size m_size;
		ir_segment m_segment;
		std::shared_ptr<Expression> m_expr;
	};


	class Statement
	{
	protected:
		statement_type m_statement_type;

		Statement(statement_type t) : m_statement_type(t) {}
		virtual ~Statement() {};

	public:
		statement_type get_type() const
		{
			return this->m_statement_type;
		}

	public:
		virtual void to_string(std::ostream& stream) const = 0;
	};
	std::ostream& operator<<(std::ostream& stream, const Statement& expr);
	std::ostream& operator<<(std::ostream& stream, const Statement* expr);

	// Assign (x = y)
	class Assign : public Statement
	{
	public:
		Assign(const std::shared_ptr<Expression> &left, const std::shared_ptr<Expression> &right);

		virtual void to_string(std::ostream& stream) const override;

		std::shared_ptr<Expression> get_left() const;
		std::shared_ptr<Expression> get_right() const;
		void set_left(const std::shared_ptr<Expression> &expr)
		{
			this->m_left = expr;
		}
		void set_right(const std::shared_ptr<Expression> &expr)
		{
			this->m_right = expr;
		}

	private:
		std::shared_ptr<Expression> m_left, m_right;
	};

	// Push x
	class Push : public Statement
	{
	public:
		Push(const std::shared_ptr<Expression> &expr) : Statement(ir_statement_push)
		{
			this->m_expr = expr;
		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Push (" << this->m_expr << ")";
		}

		std::shared_ptr<Expression> get_expression() const
		{
			return this->m_expr;
		}
		void set_expression(const std::shared_ptr<Expression> &expr)
		{
			this->m_expr = expr;
		}

	private:
		std::shared_ptr<Expression> m_expr;
	};

	// Pop y
	class Pop : public Statement
	{
	public:
		Pop(const std::shared_ptr<Expression> &expr) : Statement(ir_statement_pop)
		{
			this->m_expr = expr;
		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Pop (" << this->m_expr << ")";
		}

		std::shared_ptr<Expression> get_expression() const
		{
			return this->m_expr;
		}
		void set_expression(const std::shared_ptr<Expression> &expr)
		{
			this->m_expr = expr;
		}

	private:
		std::shared_ptr<Expression> m_expr;
	};

	// UnaryOperation
	class UnaryOperation : public Expression
	{
	protected:
		UnaryOperation(const std::shared_ptr<Expression> &op) : Expression(expr_unary_operation)
		{
			this->m_op = op;
		}

	public:
		std::shared_ptr<Expression> get_expression() const
		{
			return this->m_op;
		}
		void set_expression(const std::shared_ptr<Expression> &expr)
		{
			this->m_op = expr;
		}

	protected:
		std::shared_ptr<Expression> m_op;
	};
	class Inc : public UnaryOperation
	{
	public:
		Inc(const std::shared_ptr<Expression> &op) : UnaryOperation(op)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Inc(" << this->m_op << ")";
		}
	};
	class Dec : public UnaryOperation
	{
	public:
		Dec(const std::shared_ptr<Expression> &op) : UnaryOperation(op)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Dec(" << this->m_op << ")";
		}
	};
	class Not : public UnaryOperation
	{
	public:
		Not(const std::shared_ptr<Expression> &op) : UnaryOperation(op)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Not(" << this->m_op << ")";
		}
	};
	class Neg : public UnaryOperation
	{
	public:
		Neg(const std::shared_ptr<Expression> &op) : UnaryOperation(op)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Neg(" << this->m_op << ")";
		}
	};

	// BinaryOperation
	class BinaryOperation : public Expression
	{
	protected:
		BinaryOperation(const std::shared_ptr<Expression> &op0, const std::shared_ptr<Expression> &op1, binary_operation_type t = binary_op_invalid) : Expression(expr_binary_operation)
		{
			this->m_op0 = op0;
			this->m_op1 = op1;
			this->m_binary_type = t;
		}
		virtual ~BinaryOperation() {}

		std::shared_ptr<Expression> m_op0, m_op1;
		binary_operation_type m_binary_type;

	public:
		binary_operation_type get_binary_type() const
		{
			return this->m_binary_type;
		}
		std::shared_ptr<Expression> get_expression0() const
		{
			return this->m_op0;
		}
		std::shared_ptr<Expression> get_expression1() const
		{
			return this->m_op1;
		}
		void set_expression0(const std::shared_ptr<Expression> &expr)
		{
			this->m_op0 = expr;
		}
		void set_expression1(const std::shared_ptr<Expression> &expr)
		{
			this->m_op1 = expr;
		}

		virtual void to_string(std::ostream& stream) const = 0;
	};
	class Add : public BinaryOperation
	{
	public:
		Add(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1, binary_op_add)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Add(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Sub : public BinaryOperation
	{
	public:
		Sub(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1, binary_op_sub)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Sub(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};

	class Shl : public BinaryOperation
	{
	public:
		Shl(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Shl(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Shr : public BinaryOperation
	{
	public:
		Shr(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Shr(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};

	class Rcr : public BinaryOperation
	{
	public:
		Rcr(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Rcr(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Rcl : public BinaryOperation
	{
	public:
		Rcl(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Rcl(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Rol : public BinaryOperation
	{
	public:
		Rol(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Rol(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Ror : public BinaryOperation
	{
	public:
		Ror(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Ror(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};

	class And : public BinaryOperation
	{
	public:
		And(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "And(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Or : public BinaryOperation
	{
	public:
		Or(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Or(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Xor : public BinaryOperation
	{
	public:
		Xor(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1, binary_op_xor)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Xor(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};

	class Cmp : public BinaryOperation
	{
	public:
		Cmp(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Cmp(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};
	class Test : public BinaryOperation
	{
	public:
		Test(const std::shared_ptr<Expression> &op0,
			const std::shared_ptr<Expression> &op1) : BinaryOperation(op0, op1)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Test(" << this->m_op0 << ", " << this->m_op1 << ")";
		}
	};

	// special
	class Cpuid : public Statement
	{
	public:
		Cpuid() : Statement(ir_statement_cpuid)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Cpuid";
		}
	};
	class Rdtsc : public Statement
	{
	public:
		Rdtsc() : Statement(ir_statement_rdtsc)
		{

		}

		virtual void to_string(std::ostream& stream) const override
		{
			stream << "Rdtsc";
		}
	};
}