add_rules("mode.debug", "mode.release")

target("SymbolProvider")
    set_kind("static")
    set_languages("c++17")
    add_files("src/**.cpp")
