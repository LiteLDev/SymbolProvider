add_rules("mode.debug", "mode.release")

if is_mode("debug") then
    set_runtimes("MDd")
else
    set_runtimes("MD")
end

target("SymbolProvider")
    set_kind("static")
    set_languages("c++17")
    add_files("src/**.cpp")
