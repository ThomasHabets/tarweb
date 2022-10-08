/**
 * Simple main-wrapper for printing exceptions.
 */
#include <cstdlib>
#include <iostream>
#include <stdexcept>

int mainwrap(int argc, char** argv);

int main(int argc, char** argv)
{
    try {
        return mainwrap(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        exit(EXIT_FAILURE);
    }
}
