#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_PATH 260

// Safe path construction function that should be used instead of sprintf
static int safe_build_path(char *dest, size_t dest_size, const char *windir, const char *filename) {
    size_t required = strlen(windir) + strlen("\\System32\\") + strlen(filename) + 1;
    if (required > dest_size) {
        return -1; // Would overflow
    }
    snprintf(dest, dest_size, "%s\\System32\\%s", windir, filename);
    return 0;
}

START_TEST(test_path_construction_bounds)
{
    // Invariant: Path construction must never write beyond buffer bounds
    char lpPath[MAX_PATH];
    
    const char *payloads[] = {
        // Exploit case: oversized path that would overflow MAX_PATH
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        // Boundary case: exactly at limit
        "C:\\Windows\\VeryLongPathNameThatApproachesButDoesNotExceedTheMaximumAllowedPathLengthForWindowsSystemsWhichIsTypicallyTwoHundredAndSixtyCharactersIncludingNullTerminator",
        // Valid input: normal Windows directory
        "C:\\Windows"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        memset(lpPath, 'X', sizeof(lpPath)); // Canary pattern
        
        int result = safe_build_path(lpPath, sizeof(lpPath), payloads[i], "notepad.exe");
        
        // Security invariant: function must reject oversized inputs or produce valid bounded output
        if (result == 0) {
            ck_assert_uint_lt(strlen(lpPath), MAX_PATH);
        }
        // If result == -1, overflow was prevented (correct behavior)
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_path_construction_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}