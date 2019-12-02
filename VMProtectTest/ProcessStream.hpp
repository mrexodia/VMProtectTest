#pragma once

#include "AbstractStream.hpp"

class ProcessStream : public AbstractStream
{
public:
	ProcessStream(bool x86_64 = false);
	~ProcessStream();

	bool isOpen() const override;
	bool open(unsigned long pid);
	void close() override;

	SIZE_T read(void* buf, SIZE_T size) override;
	SIZE_T write(const void* buf, SIZE_T size) override;

	unsigned long long pos() override;
	void seek(unsigned long long pos) override;

private:
	unsigned long m_processId;
	HANDLE m_processHandle;
	unsigned long long m_pos;
};