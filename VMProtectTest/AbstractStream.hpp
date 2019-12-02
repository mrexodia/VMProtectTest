#pragma once

#include "x86_instruction.hpp"

class AbstractStream
{
protected:
	bool m_x86_64;

	AbstractStream(bool x86_64 = false);
	virtual ~AbstractStream();

public:
	virtual bool isOpen() const = 0;
	virtual void close() = 0;
	virtual SIZE_T read(void* buf, SIZE_T size) = 0;
	virtual SIZE_T write(const void* buf, SIZE_T size) = 0;

	virtual unsigned long long pos() = 0;
	virtual void seek(unsigned long long pos) = 0;

	std::shared_ptr<x86_instruction> readNext();
};