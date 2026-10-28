# Questionnaire

The column names in [responses-template.csv](responses-template.csv) are in brackets.

## Before the tasks (once)

1. Role [`role`]:
   - developer;
   - platform or DevOps engineer;
   - SRE;
   - security engineer;
   - other.
2. Years writing software professionally [`years`].
3. Have you had security training beyond a yearly awareness course? [`sec_training`]: yes / no.
4. Have you taken part in a threat-modeling session, for example STRIDE, or used a threat-modeling tool? [`tm_experience`]:
   - never;
   - once or twice;
   - regularly.
5. How often do you write or review Terraform? [`tf_frequency`]:
   - weekly;
   - monthly;
   - less often.

## For each task

You are reviewing a pull request that adds this infrastructure. Use the files you were given.

1. Can someone outside the company reach sensitive data with this configuration?
   - Yes / no [`q1_found`].
   - If yes, which data? Give the resource name [`q1_target`].
2. Which **one** line would you change first to stop that? Give file and line, for example `iam.tf:27` [`q2_line`].
3. What would you change on that line? One or two sentences [`q3_fix`, free text, coded later].
4. How confident are you in your answers? 1 = guessing, 5 = certain [`confidence`].

The time is logged automatically [`time_s`].

## After the tasks (once)

1. For the materials with the numbered steps and questions (condition C), the ten SUS items [`sus_1` … `sus_10`]:
   1 = strongly disagree, 5 = strongly agree.
   1. I think that I would like to use this system frequently.
   2. I found the system unnecessarily complex.
   3. I thought the system was easy to use.
   4. I think that I would need the support of a technical person to be able to use this system.
   5. I found the various functions in this system were well integrated.
   6. I thought there was too much inconsistency in this system.
   7. I would imagine that most people would learn to use this system very quickly.
   8. I found the system very cumbersome to use.
   9. I felt very confident using the system.
   10. I needed to learn a lot of things before I could get going with this system.
2. Rank the three kinds of material from most to least useful for this review [`rank_A`, `rank_B`, `rank_C`].
3. What, if anything, in the materials helped you decide what to change? [`open_helped`]
4. What was missing or confusing? [`open_missing`]
