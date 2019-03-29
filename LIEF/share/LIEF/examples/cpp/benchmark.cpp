/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>
#include <chrono>

#include <LIEF/LIEF.hpp>


int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_INFO);
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <Binary>" << std::endl;
    return EXIT_FAILURE;
  }

  std::chrono::time_point<std::chrono::system_clock> start, end;
  start = std::chrono::system_clock::now();

  const LIEF::Binary* binary = LIEF::Parser::parse(argv[1]);

  end = std::chrono::system_clock::now();

  delete binary;

  size_t elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
  std::cout << "[Parser] Time: " << std::dec << elapsed_seconds << "s" << std::endl;

}

