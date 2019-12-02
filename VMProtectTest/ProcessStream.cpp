#include "pch.h"

#include "ProcessStream.hpp"

ProcessStream::ProcessStream(bool x86_64) : AbstractStream(x86_64)
{
	this->m_processId = 0;
	this->m_processHandle = NULL;
	this->m_pos = 0;
}
ProcessStream::~ProcessStream()
{
	this->close();
}

bool ProcessStream::isOpen() const
{
	return this->m_processHandle != NULL;
}

bool ProcessStream::open(unsigned long pid)
{
	this->close();
	this->m_processId = pid;
	this->m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return this->isOpen();
}

void ProcessStream::close()
{
	if (this->m_processHandle != NULL)
	{
		CloseHandle(this->m_processHandle);
		this->m_processHandle = NULL;
	}
}

SIZE_T ProcessStream::read(void* buf, SIZE_T size)
{
	if (!this->isOpen())
		throw std::runtime_error("process is not open");

	LPCVOID address = reinterpret_cast<LPCVOID>(this->m_pos);
	SIZE_T readBytes = 0;
	if (!ReadProcessMemory(this->m_processHandle, address, buf, size, &readBytes))
	{
		DWORD lastError = GetLastError();
		std::stringstream ss;
		ss << "ReadProcessMemory(" << address << ") failed with error code: " << lastError;
		throw std::runtime_error(ss.str());
	}

	this->m_pos += readBytes;
	return readBytes;
}

SIZE_T ProcessStream::write(const void* buf, SIZE_T size)
{
	if (!this->isOpen())
		throw std::runtime_error("process is not open");

	LPVOID address = reinterpret_cast<LPVOID>(this->m_pos);
	SIZE_T writtenBytes = 0;
	if (!WriteProcessMemory(this->m_processHandle, address, buf, size, &writtenBytes))
	{
		DWORD lastError = GetLastError();
		std::stringstream ss;
		ss << "WriteProcessMemory failed with error code: " << lastError;
		throw std::runtime_error(ss.str());
	}

	this->m_pos += writtenBytes;
	return writtenBytes;
}

unsigned long long ProcessStream::pos()
{
	return this->m_pos;
}

void ProcessStream::seek(unsigned long long pos)
{
	if (!this->isOpen())
		throw std::runtime_error("process is not open");

	this->m_pos = pos;
}