#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include "iced.hpp"

struct NGBasicBlock {
	std::uint64_t start_address;
	std::uint64_t end_address;
};

struct NGFunction {
	std::uint64_t start_address;
	std::uint8_t section_index;
	std::vector<NGBasicBlock> blocks;
};


class Engine {
public:
	Engine ( const std::vector<std::uint8_t>& binary, std::string_view identifier );
	~Engine ( );
};