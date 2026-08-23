/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.geode.management.internal.cli.functions;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.geode.cache.Cache;
import org.apache.geode.cache.Region;
import org.apache.geode.cache.execute.FunctionContext;
import org.apache.geode.cache.snapshot.RegionSnapshotService;
import org.apache.geode.cache.snapshot.SnapshotOptions;
import org.apache.geode.cache.snapshot.SnapshotOptions.SnapshotFormat;
import org.apache.geode.internal.cache.InternalCache;
import org.apache.geode.internal.cache.snapshot.SnapshotOptionsImpl;
import org.apache.geode.management.cli.CliFunction;
import org.apache.geode.management.internal.functions.CliFunctionResult;
import org.apache.geode.management.internal.i18n.CliStrings;
import org.apache.geode.util.internal.GeodeGlossary;

/***
 * Function which carries out the export of a region to a file on a member. Uses the
 * RegionSnapshotService to export the data
 *
 * <p>
 * The export path is supplied by the caller, so this member - not the member that parsed the
 * command - is responsible for deciding whether it may be written to. Every path is canonicalized
 * and then checked against the directories this member permits exports into, so that neither an
 * absolute path, nor a "../" sequence, nor a symbolic link can place the snapshot outside them.
 */
public class ExportDataFunction extends CliFunction<String[]> {
  private static final long serialVersionUID = 1L;

  private static final String ID =
      "org.apache.geode.management.internal.cli.functions.ExportDataFunction";

  /**
   * System property naming additional directories this member permits {@code export data} to write
   * into. Several directories may be listed, separated by {@link File#pathSeparator}. Exports into
   * sub-directories of a permitted directory are allowed.
   *
   * <p>
   * The member's working directory is always permitted - it is where a relative export path lands,
   * and where the member already writes its logs and disk stores - so when this property is not
   * set it is the only directory an export may be written to.
   */
  public static final String EXPORT_DATA_DIRS_PROPERTY =
      GeodeGlossary.GEMFIRE_PREFIX + "export.data.dirs";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public CliFunctionResult executeFunction(FunctionContext<String[]> context) throws Exception {
    final String[] args = context.getArguments();
    if (args.length < 3) {
      throw new IllegalStateException(
          "Arguments length does not match required length. Export command may have been sent from incompatible older version");
    }
    final String regionName = args[0];
    final String fileName = args[1];
    final boolean parallel = Boolean.parseBoolean(args[2]);
    CliFunctionResult result;

    Cache cache = ((InternalCache) context.getCache()).getCacheForProcessingClientRequests();
    Region<Object, Object> region = cache.getRegion(regionName);
    String hostName = cache.getDistributedSystem().getDistributedMember().getHost();
    if (region != null) {
      RegionSnapshotService<Object, Object> snapshotService = region.getSnapshotService();
      final File exportFile = validateExportPath(fileName);
      if (parallel) {
        SnapshotOptions<Object, Object> options = new SnapshotOptionsImpl<>().setParallelMode(true);
        snapshotService.save(exportFile, SnapshotFormat.GEODE, options);
      } else {
        snapshotService.save(exportFile, SnapshotFormat.GEODE);
      }

      String successMessage = CliStrings.format(CliStrings.EXPORT_DATA__SUCCESS__MESSAGE,
          regionName, exportFile.getCanonicalPath(), hostName);
      result = new CliFunctionResult(context.getMemberName(), CliFunctionResult.StatusState.OK,
          successMessage);
    } else {
      result = new CliFunctionResult(context.getMemberName(), CliFunctionResult.StatusState.ERROR,
          CliStrings.format(CliStrings.REGION_NOT_FOUND, regionName));
    }

    return result;
  }

  /**
   * Resolves the requested export path and confirms that it is contained in one of the directories
   * this member permits exports into.
   *
   * @param fileName the path requested by the caller, which may be relative, may be absolute and
   *        may contain "../" sequences or symbolic links
   * @return the canonical file to export to, never containing a parent directory reference
   * @throws SecurityException if the requested path resolves outside every permitted directory
   */
  static File validateExportPath(String fileName) throws IOException {
    File exportFile = new File(fileName).getCanonicalFile();
    List<File> permittedDirs = permittedExportDirs();

    for (File permittedDir : permittedDirs) {
      if (exportFile.toPath().startsWith(permittedDir.toPath())) {
        return exportFile;
      }
    }

    throw new SecurityException(String.format(
        "Cannot export to %s: the path is outside the directories this member permits exports into (%s). Set the %s system property on the member to permit other directories.",
        exportFile, permittedDirs, EXPORT_DATA_DIRS_PROPERTY));
  }

  private static List<File> permittedExportDirs() throws IOException {
    List<File> permittedDirs = new ArrayList<>();
    permittedDirs.add(new File(System.getProperty("user.dir")).getCanonicalFile());

    String configuredDirs = System.getProperty(EXPORT_DATA_DIRS_PROPERTY);
    if (configuredDirs != null) {
      for (String configuredDir : configuredDirs.split(File.pathSeparator)) {
        if (!configuredDir.trim().isEmpty()) {
          permittedDirs.add(new File(configuredDir.trim()).getCanonicalFile());
        }
      }
    }

    return permittedDirs;
  }
}
