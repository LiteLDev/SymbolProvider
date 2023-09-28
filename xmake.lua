add_rules("mode.debug", "mode.release")

target("SymbolProvider")
    set_kind("static")
    set_languages("c++20")
    add_files("src/**.cpp")
