" make
let g:syntastic_c_checkers = ["gcc"]
let g:syntastic_c_compiler = "clang-12"
let g:syntastic_c_check_header = 1
let g:syntastic_c_compiler_options = ""
let g:syntastic_c_include_dirs = ["include", "../deps/usr/include"]

let g:ctrlp_custom_ignore = {
			\ 'dir':  '\v[\/](build/*|\.(git|hg|svn))$',
			\ 'file': '\v\.(exe|so|dll|o|a|zip|tar)$',
			\ }

