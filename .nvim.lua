---@type CompileModeOpts
vim.g.compile_mode = vim.tbl_deep_extend("force", vim.g.compile_mode or {}, {
  default_command = "bear -- make -j24",   -- or whatever this project needs
})
