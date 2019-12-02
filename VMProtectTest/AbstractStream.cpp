#include "pch.h"

#include "AbstractStream.hpp"

AbstractStream::AbstractStream(bool x86_64)
{
	this->m_x86_64 = x86_64;
}
AbstractStream::~AbstractStream()
{
}

std::shared_ptr<x86_instruction> AbstractStream::readNext()
{
	constexpr unsigned int bufSize = 16;
	xed_uint8_t buf[bufSize];
	unsigned long long address = this->pos();
	unsigned int readBytes = this->read(buf, bufSize);

	std::shared_ptr<x86_instruction> inst = std::make_shared<x86_instruction>(address);
	inst->decode(buf, readBytes, 
		this->m_x86_64 ? XED_MACHINE_MODE_LONG_64 : XED_MACHINE_MODE_LEGACY_32, 
		this->m_x86_64 ? XED_ADDRESS_WIDTH_64b : XED_ADDRESS_WIDTH_32b);

	this->seek(inst->get_addr() + inst->get_length());
	return inst;
}