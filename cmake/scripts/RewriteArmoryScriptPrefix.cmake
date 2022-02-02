file(READ ${script_file} script_contents)

string(REGEX REPLACE " /usr" " ${prefix}" script_edited ${script_contents})

file(MAKE_DIRECTORY ${script_dir}/script_tmp)

file(WRITE ${script_dir}/script_tmp/${script_name} ${script_edited})

file(
    COPY ${script_dir}/script_tmp/${script_name}
    DESTINATION ${script_dir}
    FILE_PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

file(REMOVE_RECURSE ${script_dir}/script_tmp)
