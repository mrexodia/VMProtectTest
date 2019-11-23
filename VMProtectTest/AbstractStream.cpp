#include "pch.h"

#include "AbstractStream.hpp"

AbstractStream::AbstractStream()
{
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
	inst->decode(buf, readBytes);

	this->seek(inst->get_addr() + inst->get_length());
	return inst;
}