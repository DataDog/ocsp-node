{
    "targets": [
        {
            "target_name": "ocsp",
            "sources": ["src/helper.cpp", "src/ocsp.cpp", "src/binding.cpp"],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
