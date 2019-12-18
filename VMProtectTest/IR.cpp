#include "pch.h"

#include "IR.hpp"

namespace IR
{
	int Variable::s_index = 0;

	//
	std::string get_size_string(ir_size size)
	{
		switch (size)
		{
			case IR::ir_size_b: return "byte";
			case IR::ir_size_w: return "word";
			case IR::ir_size_d: return "dword";
			case IR::ir_size_q: return "qword";

			default:
				throw std::invalid_argument("invalid size");
		}
	}
	std::string get_segment_string(ir_segment segment)
	{
		switch (segment)
		{
			case ir_segment_scratch: return "scratch";
			case ir_segment_cs: return "cs";
			case ir_segment_ds: return "ds";
			case ir_segment_es: return "es";
			case ir_segment_fs: return "fs";
			case ir_segment_gs: return "gs";
			case ir_segment_ss: return "ss";
			case ir_segment_regular: return "regular";
			default:
				throw std::invalid_argument("invalid segment");
		}
	}

	// Register
	Register::Register(triton::uint64 offset) : Expression(expr_register)
	{
		if (offset > 0xFF)
			throw std::runtime_error("offset is bigger than 0xFF");

		char name[64];
		sprintf_s(name, 64, "VM_REG_%02llX", offset);
		this->m_name.assign(name);
		this->m_offset = offset;
	}
	Register::Register(const triton::arch::Register &triton_register) : Expression(expr_register)
	{
		this->m_name = triton_register.getName();
		this->m_offset = 0;
		this->m_register = triton_register;
	}
	void Register::to_string(std::ostream& stream) const
	{
		stream << this->get_name();
	}
	std::string Register::get_name() const
	{
		return this->m_name;
	}
	triton::uint64 Register::get_offset() const
	{
		return this->m_offset;
	}


	// Memory
	Memory::Memory(const std::shared_ptr<Expression> &expr, ir_segment segment, ir_size size) : Expression(expr_memory)
	{
		this->m_expr = expr;
		this->m_segment = segment;
		this->m_size = size;
	}
	void Memory::to_string(std::ostream& stream) const
	{
		stream << get_size_string(m_size) << " ptr " << get_segment_string(this->m_segment) << ":[" << this->m_expr << "]";
	}
	std::shared_ptr<Expression> Memory::get_expression() const
	{
		return this->m_expr;
	}


	// Variable
	Variable::Variable(ir_size size) : Expression(expr_variable)
	{
		this->m_name = "Temp" + std::to_string(++s_index);
		this->m_size = size;
	}
	Variable::Variable(const std::string &name, ir_size size) : Expression(expr_variable)
	{
		this->m_name = name;
		this->m_size = size;
	}
	void Variable::to_string(std::ostream& stream) const
	{
		stream << this->get_name() << "(" << this->m_size << "bytes)";
	}
	std::string Variable::get_name() const
	{
		return this->m_name;
	}
	std::shared_ptr<Variable> Variable::create_variable(triton::uint32 size)
	{
		auto temp_variable = std::make_shared<Variable>((IR::ir_size)size);
		return temp_variable;
	}


	// Immediate
	Immediate::Immediate(triton::uint64 immediate) : Expression(expr_immediate)
	{
		this->m_immediate = immediate;
	}
	void Immediate::to_string(std::ostream& stream) const
	{
		stream << "0x" << std::hex << this->m_immediate << std::dec;
	}


	// Dereference
	Dereference::Dereference(const std::shared_ptr<Expression> &expr, ir_segment segment, ir_size size) : Expression(expr_deref)
	{
		this->m_expr = expr;
		this->m_segment = segment;
		this->m_size = size;
	}
	std::shared_ptr<Expression> Dereference::get_expression() const
	{
		return this->m_expr;
	}
	void Dereference::set_expression(const std::shared_ptr<Expression> &expr)
	{
		this->m_expr = expr;
	}
	void Dereference::to_string(std::ostream& stream) const
	{
		// Deref(segment, expr, size)
		stream << "Deref(" << get_segment_string(this->m_segment) << ", "
			<< this->get_expression() << ", "
			<< get_size_string(this->m_size) << ")";
	}


	// Assign
	Assign::Assign(const std::shared_ptr<Expression> &left, const std::shared_ptr<Expression> &right) : Statement(ir_statement_assign)
	{
		this->m_left = left;
		this->m_right = right;
	}
	void Assign::to_string(std::ostream& stream) const
	{
		stream << this->get_left() << "=" << this->get_right();
	}
	std::shared_ptr<Expression> Assign::get_left() const
	{
		return this->m_left;
	}
	std::shared_ptr<Expression> Assign::get_right() const
	{
		return this->m_right;
	}


	//
	std::ostream& operator<<(std::ostream& stream, const Expression& expr)
	{
		expr.to_string(stream);
		return stream;
	}
	std::ostream& operator<<(std::ostream& stream, const Expression* expr)
	{
		expr->to_string(stream);
		return stream;
	}

	std::ostream& operator<<(std::ostream& stream, const Statement& expr)
	{
		expr.to_string(stream);
		return stream;
	}
	std::ostream& operator<<(std::ostream& stream, const Statement* expr)
	{
		expr->to_string(stream);
		return stream;
	}

	std::shared_ptr<Expression> simplify_expression(const std::shared_ptr<Expression> &expression)
	{
		if (expression->get_type() == IR::expr_binary_operation)
		{
			std::shared_ptr<IR::BinaryOperation> binary_op = std::dynamic_pointer_cast<IR::BinaryOperation>(expression);
			if (binary_op->get_binary_type() == IR::binary_op_add
				|| binary_op->get_binary_type() == IR::binary_op_sub
				|| binary_op->get_binary_type() == IR::binary_op_xor)
			{
				// (add|sub|xor) X,0 -> X
				if (binary_op->get_expression0()->get_type() == IR::expr_immediate
					&& std::dynamic_pointer_cast<IR::Immediate>(binary_op->get_expression0())->get_value() == 0)
				{
					return binary_op->get_expression1();
				}
				else if (binary_op->get_expression1()->get_type() == IR::expr_immediate
					&& std::dynamic_pointer_cast<IR::Immediate>(binary_op->get_expression1())->get_value() == 0)
				{
					return binary_op->get_expression0();
				}
			}

			// return <expr, imm>
			auto parse_binary_expression = [](const std::shared_ptr<IR::BinaryOperation> &binary_op) ->
				std::tuple<std::shared_ptr<IR::Expression>, std::shared_ptr<IR::Expression>>
			{
				std::shared_ptr<IR::Expression> immediate_node;
				std::shared_ptr<IR::Expression> the_other_node;

				auto expr0 = binary_op->get_expression0();
				auto expr1 = binary_op->get_expression1();
				if (expr0->get_type() == IR::expr_immediate)
				{
					immediate_node = expr0;
					the_other_node = expr1;
				}
				else if (expr1->get_type() == IR::expr_immediate)
				{
					the_other_node = expr0;
					immediate_node = expr1;
				}
				return std::make_tuple(the_other_node, immediate_node);
			};

			// add(add(x, imm0), imm1) -> add(x, imm0 + imm1)
			if (binary_op->get_binary_type() == IR::binary_op_add
				|| binary_op->get_binary_type() == IR::binary_op_sub)
			{
				std::shared_ptr<IR::Expression> possible_binary_expr, imm_node_0;
				std::tie(possible_binary_expr, imm_node_0) = parse_binary_expression(binary_op);
				if (possible_binary_expr && imm_node_0 && possible_binary_expr->get_type() == IR::expr_binary_operation)
				{
					std::shared_ptr<IR::BinaryOperation> sub_binary_node = std::dynamic_pointer_cast<IR::BinaryOperation>(possible_binary_expr);
					if (sub_binary_node->get_binary_type() == IR::binary_op_add || sub_binary_node->get_binary_type() == IR::binary_op_sub)
					{
						std::shared_ptr<IR::Expression> rest_of_node, imm_node_1;
						std::tie(rest_of_node, imm_node_1) = parse_binary_expression(sub_binary_node);
						if (rest_of_node && imm_node_1)
						{
							triton::sint64 value0 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_0)->get_value();
							if (binary_op->get_binary_type() == IR::binary_op_sub)
								value0 = -value0;

							triton::sint64 value1 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_1)->get_value();
							if (sub_binary_node->get_binary_type() == IR::binary_op_sub)
								value1 = -value1;

							return std::make_shared<IR::Add>(rest_of_node, std::make_shared<IR::Immediate>(value0 + value1));
						}
					}
				}
			}
			else if (binary_op->get_binary_type() == IR::binary_op_xor)
			{
				std::shared_ptr<IR::Expression> possible_binary_expr, imm_node_0;
				std::tie(possible_binary_expr, imm_node_0) = parse_binary_expression(binary_op);
				if (possible_binary_expr && imm_node_0 && possible_binary_expr->get_type() == IR::expr_binary_operation)
				{
					std::shared_ptr<IR::BinaryOperation> sub_binary_node = std::dynamic_pointer_cast<IR::BinaryOperation>(possible_binary_expr);
					if (sub_binary_node->get_binary_type() == IR::binary_op_xor)
					{
						std::shared_ptr<IR::Expression> rest_of_node, imm_node_1;
						std::tie(rest_of_node, imm_node_1) = parse_binary_expression(sub_binary_node);
						if (rest_of_node && imm_node_1)
						{
							triton::sint64 value0 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_0)->get_value();
							triton::sint64 value1 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_1)->get_value();
							return std::make_shared<IR::Xor>(rest_of_node, std::make_shared<IR::Immediate>(value0 ^ value1));
						}
					}
				}
			}

			// simplify
			std::shared_ptr<Expression> simplified_expr0 = simplify_expression(binary_op->get_expression0());
			std::shared_ptr<Expression> simplified_expr1 = simplify_expression(binary_op->get_expression1());
			binary_op->set_expression0(simplified_expr0);
			binary_op->set_expression1(simplified_expr1);
		}
		return expression;
	}
}