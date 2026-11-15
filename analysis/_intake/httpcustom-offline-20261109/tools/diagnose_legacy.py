"""Reproduce the temporary diagnostic copy used during the private-file probe."""
import argparse
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument("original",type=Path)
parser.add_argument("output",type=Path)
args=parser.parse_args()
source=args.original.read_text().replace('#include <regex>','#include <regex>\n#include <iostream>')
source=source.replace('}catch(...){}\n    return false;\n}\n} // namespace spdecode::offline',
    '}catch(const std::exception& e){std::cerr << e.what() << "\\n";}\n    return false;\n}\n} // namespace spdecode::offline')
args.output.write_text(source)
