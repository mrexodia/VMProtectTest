#include "pch.h"

#include "VMHandler.hpp"
#include "x86_instruction.hpp"

VMHandler::VMHandler()
{

}
VMHandler::~VMHandler()
{

}

unsigned long long VMHandler::compute_next_handler_address(void *context)
{
	// simulate instructions?
}