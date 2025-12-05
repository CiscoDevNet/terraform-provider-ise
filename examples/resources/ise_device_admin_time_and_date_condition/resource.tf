resource "ise_device_admin_time_and_date_condition" "example" {
  name = "Cond1"
  description = "My description"
  is_negate = false
  week_days = ["Monday"]
  week_days_exception = ["Tuesday"]
  start_date = "2022-05-06"
  end_date = "2022-05-10"
  exception_start_date = "2022-06-06"
  exception_end_date = "2022-06-10"
  start_time = "08:00"
  end_time = "15:00"
  exception_start_time = "20:00"
  exception_end_time = "22:00"
}
